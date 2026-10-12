import os
import pandas as pd
from deltalake import DeltaTable, write_deltalake
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger("DeltaLakeStorage")


def _sanitize(record: dict) -> dict:
    out = {}
    for k, v in record.items():
        if v is None:
            continue                              # drop null-typed columns
        elif isinstance(v, (list, tuple, set)):
            if not v:
                continue
            out[k] = ",".join(map(str, v))
        elif isinstance(v, dict):
            continue
        elif isinstance(v, (str, int, float, bool)):
            out[k] = v
        else:
            out[k] = str(v)
    return out


class DeltaLakeStorage:
    """
    Production-grade Delta Lake storage using the native Rust-based 'deltalake' library.
    Provides ACID transactions, time-travel, and schema enforcement.
    """
    def __init__(self, table_path: str = "./data/delta-lake/logs"):
        self.table_path = table_path
        # Ensure the directory exists
        os.makedirs(os.path.dirname(self.table_path), exist_ok=True)

    def save_logs(self, logs: List[Dict[str, Any]]):
        """
        Saves a batch of logs to the Delta Table.
        Uses the 'append' mode to add new data to the existing table.
        """
        if not logs:
            return

        df = pd.DataFrame([_sanitize(r) for r in logs])
        
        try:
            # write_deltalake handles table creation if it doesn't exist
            write_deltalake(
                self.table_path, 
                df, 
                mode="append",
                schema_mode="merge" # Allows schema evolution if new fields are added
            )
            # logger.info(f"Successfully saved {len(logs)} logs to Delta Table at {self.table_path}")
        except Exception as e:
            logger.error(f"Failed to save logs to Delta Lake: {e}")
            raise

    def query_logs(self) -> pd.DataFrame:
        """
        Reads the entire Delta Table into a pandas DataFrame.
        In production, you'd typically use filters or partition pruning.
        """
        try:
            if not os.path.exists(self.table_path):
                return pd.DataFrame()
            
            dt = DeltaTable(self.table_path)
            return dt.to_pandas()
        except Exception as e:
            logger.error(f"Failed to query Delta Lake: {e}")
            return pd.DataFrame()

    def get_history(self):
        """Returns the transaction history of the Delta Table (Audit Trail)."""
        dt = DeltaTable(self.table_path)
        return dt.history()

    def query_logs_filtered(self, service: Optional[str] = None, start_date: Optional[str] = None, end_date: Optional[str] = None) -> pd.DataFrame:
        df = self.query_logs()
        if df.empty:
            return df
            
        if service:
            df = df[df.get("source", "") == service]
            
        if start_date and "timestamp" in df.columns:
            # ISO-8601 strings sort lexicographically in time order
            df = df[df["timestamp"] >= start_date]
            
        if end_date and "timestamp" in df.columns:
            df = df[df["timestamp"] <= end_date]
            
        return df

    def get_summary(self, service: Optional[str] = None, granularity: str = "hourly", date: Optional[str] = None) -> Dict[str, Any]:
        """Per-hour or per-day log and error counts, bucketed on the log timestamp (UTC)."""
        empty = {"service": service, "date": date, "granularity": granularity, "hourly_summaries": []}
        df = self.query_logs()
        if df.empty or "timestamp" not in df.columns:
            return empty

        if service and "source" in df.columns:
            df = df[df["source"] == service]

        ts = pd.to_datetime(df["timestamp"], utc=True, errors="coerce", format="ISO8601")
        df = df.assign(_ts=ts).dropna(subset=["_ts"])
        if date:
            df = df[df["_ts"].dt.strftime("%Y-%m-%d") == date]
        if df.empty:
            return empty

        freq = "D" if granularity == "daily" else "h"
        severity = df["severity"] if "severity" in df.columns else pd.Series("", index=df.index)
        df = df.assign(
            _bucket=df["_ts"].dt.floor(freq),
            _is_error=severity.astype(str).str.upper().isin(["ERROR", "CRITICAL"]),
        )
        grouped = df.groupby("_bucket").agg(total_logs=("_is_error", "size"), error_count=("_is_error", "sum"))

        buckets = [
            {
                "hour": bucket.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "total_logs": int(row.total_logs),
                "error_count": int(row.error_count),
                "error_rate": float(row.error_count) / row.total_logs,
            }
            for bucket, row in grouped.sort_index().iterrows()
        ]
        return {**empty, "hourly_summaries": buckets}
