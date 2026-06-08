import os
import pandas as pd
from typing import Dict, Any, List, Optional

class DeltaLakeStorage:
    """
    Mocking Delta Lake storage logic.
    For production, this would use delta-spark or deltalake-python.
    """
    def __init__(self, base_path: str = "./data/delta-lake"):
        self.base_path = base_path
        if not os.path.exists(self.base_path):
            os.makedirs(self.base_path)

    def save_logs(self, logs: List[Dict[str, Any]], table_name: str = "logs_raw"):
        """Saves a batch of logs to the simulated Delta Lake."""
        file_path = f"{self.base_path}/{table_name}.parquet"
        df = pd.DataFrame(logs)
        
        if os.path.exists(file_path):
            existing_df = pd.read_parquet(file_path)
            df = pd.concat([existing_df, df], ignore_index=True)
            
        df.to_parquet(file_path, compression="snappy")

    def query_logs(self, start_time: str, end_time: str) -> pd.DataFrame:
        """Query raw logs by timestamp range."""
        file_path = f"{self.base_path}/logs_raw.parquet"
        if not os.path.exists(file_path):
            return pd.DataFrame()
            
        df = pd.read_parquet(file_path)
        # Filter based on timestamp logic (simplified for mockup)
        return df[(df["timestamp"] >= start_time) & (df["timestamp"] <= end_time)]

    def query_logs_filtered(self, service: Optional[str] = None, start_date: Optional[str] = None, end_date: Optional[str] = None) -> pd.DataFrame:
        file_path = f"{self.base_path}/logs_raw.parquet"
        if not os.path.exists(file_path):
            return pd.DataFrame()
        df = pd.read_parquet(file_path)
        
        if service:
            df = df[df.get("source", "") == service]
            
        if start_date and "timestamp" in df.columns:
            df = df[df["timestamp"] >= start_date]
            
        if end_date and "timestamp" in df.columns:
            df = df[df["timestamp"] <= end_date]
            
        return df

    def get_summary(self, service: Optional[str] = None, granularity: str = "hourly", date: Optional[str] = None) -> Dict[str, Any]:
        """Compute summary statistics."""
        file_path = f"{self.base_path}/logs_raw.parquet"
        if not os.path.exists(file_path):
            return {"service": service, "date": date, "hourly_summaries": []}
            
        df = pd.read_parquet(file_path)
        if service:
            df = df[df.get("source", "") == service]
            
        if date and "timestamp" in df.columns:
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
