import os
import pandas as pd
from deltalake import DeltaTable, write_deltalake
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger("DeltaLakeStorage")

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

        df = pd.DataFrame(logs)
        
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
            # simple mock filter, assuming timestamp strings are sortable or standard ISO format
            df = df[df["timestamp"] >= start_date]
            
        if end_date and "timestamp" in df.columns:
            df = df[df["timestamp"] <= end_date]
            
        return df

    def get_summary(self, service: Optional[str] = None, granularity: str = "hourly", date: Optional[str] = None) -> Dict[str, Any]:
        """Compute summary statistics."""
        df = self.query_logs()
        if df.empty:
            return {"service": service, "date": date, "hourly_summaries": []}
            
        if service:
            df = df[df.get("source", "") == service]
            
        if date and "timestamp" in df.columns:
            # Assuming timestamp contains date, rough filter for the day
            df = df[df["timestamp"].astype(str).str.startswith(date)]
            
        total_logs = len(df)
        error_count = len(df[df.get("severity", "").astype(str).str.upper().isin(["ERROR", "CRITICAL"])])
        
        return {
            "service": service,
            "date": date,
            "hourly_summaries": [
                {
                    "hour": "Summary (mocked granular window)",
                    "total_logs": total_logs,
                    "error_count": error_count,
                    "error_rate": error_count / total_logs if total_logs > 0 else 0,
                }
            ]
        }
