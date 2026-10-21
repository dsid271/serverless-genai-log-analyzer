"""
Structured Audit Logging using Delta Lake.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional

import pandas as pd
from deltalake import write_deltalake

# Fallback logger if Delta Lake fails
logger = logging.getLogger("AuditLogger")

class AuditLogger:
    """Batches audit events into a Delta Lake table.

    A batch that cannot be written is appended to `<table_path>.spool.jsonl`
    instead of being dropped, and the spool is replayed after the next
    successful write (at-least-once: a crash mid-replay can duplicate events).
    """

    def __init__(self, table_path: str = "./data/delta-lake/audit_trail"):
        self.table_path = table_path
        self.spool_path = f"{table_path}.spool.jsonl"
        os.makedirs(os.path.dirname(self.table_path), exist_ok=True)
        self._flush_seconds = float(os.getenv("AUDIT_FLUSH_SECONDS", "5"))
        self._pending: List[Dict[str, Any]] = []
        self._pending_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

    def enqueue(self, **fields: Any) -> None:
        """Queue an audit event for the next batched commit. Never blocks on I/O."""
        event = self._event(**fields)
        with self._pending_lock:
            self._pending.append(event)
            if self._thread is None:
                self._thread = threading.Thread(target=self._flush_loop, name="audit-flush", daemon=True)
                self._thread.start()
                atexit.register(self.flush)

    def flush(self) -> None:
        with self._pending_lock:
            batch, self._pending = self._pending, []
        if batch:
            self._write(batch)

    def _flush_loop(self) -> None:
        while True:
            time.sleep(self._flush_seconds)
            self.flush()

    def log_event(
        self,
        request_id: str,
        user: str,
        action: str,
        query_params: str = "",
        results_count: int = 0,
        pii_accessed: bool = False,
        contains_pii: bool = False,
        duration_ms: float = 0.0,
        status_code: int = 200,
        error: str = "",
        detail: str = "",
    ) -> None:
        """Write a single audit event to the Delta Lake table immediately."""
        self._write([self._event(
            request_id=request_id, user=user, action=action, query_params=query_params,
            results_count=results_count, pii_accessed=pii_accessed, contains_pii=contains_pii,
            duration_ms=duration_ms, status_code=status_code, error=error, detail=detail,
        )])

    @staticmethod
    def _event(
        request_id: str,
        user: str,
        action: str,
        query_params: str = "",
        results_count: int = 0,
        pii_accessed: bool = False,
        contains_pii: bool = False,
        duration_ms: float = 0.0,
        status_code: int = 200,
        error: str = "",
        detail: str = "",
    ) -> Dict[str, Any]:
        """`detail` holds what the request asked for or returned (redacted, truncated by the caller)."""
        return {
            "timestamp": time.time(),
            "request_id": request_id,
            "user": user,
            "action": action,
            "query_params": query_params,
            "results_count": results_count,
            "pii_accessed": pii_accessed,
            "contains_pii": contains_pii,
            "duration_ms": duration_ms,
            "status_code": status_code,
            "error": error,
            "detail": detail,
        }

    def _append(self, events: List[Dict[str, Any]]) -> None:
        write_deltalake(self.table_path, pd.DataFrame(events), mode="append", schema_mode="merge")

    def _write(self, events: List[Dict[str, Any]]) -> None:
        with self._write_lock:
            try:
                self._append(events)
            except Exception as e:
                logger.error(f"Failed to write {len(events)} audit events to Delta Lake, spooling to {self.spool_path}: {e}")
                self._spool(events)
                return
            self._replay_spool()

    def _spool(self, events: List[Dict[str, Any]]) -> None:
        try:
            with open(self.spool_path, "a", encoding="utf-8") as f:
                for event in events:
                    f.write(json.dumps(event, default=str) + "\n")
        except Exception as e:
            logger.error(f"AUDIT EVENTS LOST: could not spool {len(events)} events to {self.spool_path}: {e}")

    def _replay_spool(self) -> None:
        """Called under `_write_lock` after a successful write. Leaves the spool in place on failure."""
        if not os.path.exists(self.spool_path):
            return
        events: List[Dict[str, Any]] = []
        try:
            with open(self.spool_path, encoding="utf-8") as f:
                for line in f:
                    try:
                        events.append(json.loads(line))
                    except ValueError:
                        logger.error("Skipping unreadable line in audit spool")
            if events:
                self._append(events)
            os.remove(self.spool_path)
            logger.info(f"Replayed {len(events)} spooled audit events")
        except Exception as e:
            logger.error(f"Could not replay audit spool, will retry on the next write: {e}")

    def query(self, user_filter: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Query recent audit logs.
        """
        self.flush()
        try:
            if not os.path.exists(self.table_path):
                return []
            
            from deltalake import DeltaTable
            dt = DeltaTable(self.table_path)
            df = dt.to_pandas()
            
            if "contains_pii" not in df.columns:
                df["contains_pii"] = df.get("pii_accessed", False)
            if user_filter:
                df = df[df["user"] == user_filter]
                
            # Sort by timestamp descending
            df = df.sort_values("timestamp", ascending=False).head(limit)

            # Rows written before a column existed come back as NaN in numeric columns,
            # which is not valid JSON (the endpoint would 500). Return null instead.
            df = df.astype(object).where(df.notna(), None)

            return df.to_dict(orient="records")
            
        except Exception as e:
            logger.error(f"Failed to query audit logs: {e}")
            return []

audit_logger = AuditLogger()
