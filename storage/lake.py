import json
import os
import pandas as pd
from deltalake import DeltaTable, write_deltalake
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger("DeltaLakeStorage")


def _env_paths(name: str) -> List[str]:
    return [p.strip() for p in os.getenv(name, "").split(",") if p.strip()]


def _text(value: Any) -> Optional[str]:
    """Comparable string form; 500, 500.0 (ints read back with nulls) and "500" all give "500"."""
    if value is None or (pd.api.types.is_scalar(value) and pd.isna(value)):
        return None
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _json_obj(value: Any) -> Dict[str, Any]:
    try:
        parsed = json.loads(value) if isinstance(value, str) else None
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


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
    def __init__(self, table_path: Optional[str] = None, read_paths: Optional[List[str]] = None):
        self.table_path = table_path or os.path.join(os.getenv("DELTA_LAKE_PATH", "./data/delta-lake"), "logs")
        # Extra tables queried alongside this one, read-only (e.g. the Spark job's logs_stream).
        paths = read_paths if read_paths is not None else _env_paths("DELTA_LAKE_READ_PATHS")
        self.read_paths = [p for p in paths if os.path.abspath(p) != os.path.abspath(self.table_path)]
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

    @staticmethod
    def _read_table(path: str, columns: Optional[List[str]]) -> pd.DataFrame:
        dt = DeltaTable(path)
        if columns is None:
            return dt.to_pandas()
        names = {f.name for f in dt.schema().fields}
        present = [c for c in columns if c in names]
        # Spark rows keep fields outside its fixed schema only in the `record` JSON column.
        nested = [c for c in columns if c not in names] if "record" in names else []
        read = present + (["record"] if nested else [])
        if not read:
            return pd.DataFrame()
        df = dt.to_pandas(columns=read)
        if nested:
            parsed = df["record"].map(_json_obj)
            for c in nested:
                df[c] = parsed.map(lambda r, c=c: r.get(c))
            if "record" not in columns:
                df = df.drop(columns="record")
        return df

    def query_logs(self, columns: Optional[List[str]] = None) -> pd.DataFrame:
        """
        Reads this table plus every DELTA_LAKE_READ_PATHS table into one DataFrame.
        `columns` limits what is read; missing columns are absent or null.
        In production, you'd typically use filters or partition pruning.
        """
        frames = []
        for i, path in enumerate([self.table_path] + self.read_paths):
            if not os.path.exists(path):
                continue
            try:
                df = self._read_table(path, columns)
            except Exception as e:
                if i == 0:
                    logger.error(f"Failed to query Delta Lake: {e}")
                else:
                    logger.warning(f"Skipping unreadable Delta table {path}: {e}")
                continue
            if not df.empty:
                frames.append(df)
        if not frames:
            return pd.DataFrame()
        return frames[0] if len(frames) == 1 else pd.concat(frames, ignore_index=True)

    def aggregate(
        self,
        filters: Optional[Dict[str, Any]] = None,
        group_by: Optional[List[str]] = None,
        start: Optional[pd.Timestamp] = None,
        end: Optional[pd.Timestamp] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Count logs matching exact-value `filters` (a list value means any of), grouped by `group_by`.

        Values are compared as strings, so 500 matches "500". Rows without a parseable
        timestamp are dropped when `start` or `end` is given."""
        filters, group_by = filters or {}, group_by or []
        columns = list(dict.fromkeys(["timestamp", *filters, *group_by]))
        df = self.query_logs(columns=columns)
        scanned = len(df)
        if df.empty:
            return {"rows": [], "total": 0, "scanned": 0}

        for col in columns:
            if col not in df.columns:
                df[col] = None
        if start is not None or end is not None:
            ts = pd.to_datetime(df["timestamp"], utc=True, errors="coerce", format="ISO8601")
            keep = ts.notna()
            if start is not None:
                keep &= ts >= start
            if end is not None:
                keep &= ts <= end
            df = df[keep]
        for col, value in filters.items():
            wanted = {_text(v) for v in value} if isinstance(value, (list, tuple, set)) else {_text(value)}
            df = df[df[col].map(_text).isin(wanted)]

        total = len(df)
        if not group_by:
            return {"rows": [{"count": total}], "total": total, "scanned": scanned}
        keys = pd.DataFrame({g: df[g].map(_text) for g in group_by})
        counts = keys.groupby(group_by, dropna=False).size().sort_values(ascending=False, kind="stable").head(limit)
        rows = []
        for key, n in counts.items():
            key = key if isinstance(key, tuple) else (key,)
            rows.append({**{g: None if pd.isna(k) else k for g, k in zip(group_by, key)}, "count": int(n)})
        return {"rows": rows, "total": total, "scanned": scanned}

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
        df = self.query_logs(columns=["timestamp", "source", "severity"])
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
