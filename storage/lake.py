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
