"""
Structured Audit Logging using Delta Lake.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional

import pandas as pd
from deltalake import write_deltalake

# Fallback logger if Delta Lake fails
logger = logging.getLogger("AuditLogger")

class AuditLogger:
    def __init__(self, table_path: str = "./data/delta-lake/audit_trail"):
        self.table_path = table_path
        os.makedirs(os.path.dirname(self.table_path), exist_ok=True)

    def log_event(
        self,
        request_id: str,
        user: str,
        action: str,
        query_params: str = "",
        results_count: int = 0,
        pii_accessed: bool = False,
        duration_ms: float = 0.0,
        status_code: int = 200,
        error: str = "",
    ) -> None:
        """
        Write a single audit event to the Delta Lake table.
        This is typically called in a BackgroundTask.
        """
        event = {
            "timestamp": time.time(),
            "request_id": request_id,
            "user": user,
            "action": action,
            "query_params": query_params,
            "results_count": results_count,
            "pii_accessed": pii_accessed,
            "duration_ms": duration_ms,
            "status_code": status_code,
            "error": error,
        }

        try:
            df = pd.DataFrame([event])
            write_deltalake(
                self.table_path,
                df,
                mode="append",
                schema_mode="merge",
            )
        except Exception as e:
            logger.error(f"Failed to write audit log to Delta Lake: {e}. Event: {event}")

    def query(self, user_filter: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Query recent audit logs.
        """
        try:
            if not os.path.exists(self.table_path):
                return []
            
            from deltalake import DeltaTable
            dt = DeltaTable(self.table_path)
            df = dt.to_pandas()
            
            if user_filter:
                df = df[df["user"] == user_filter]
                
            # Sort by timestamp descending
            df = df.sort_values("timestamp", ascending=False)
            
            return df.head(limit).to_dict(orient="records")
            
        except Exception as e:
            logger.error(f"Failed to query audit logs: {e}")
            return []

audit_logger = AuditLogger()
