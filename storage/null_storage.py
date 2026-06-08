from typing import Dict, Any, List, Optional

class DeltaLakeStorage:
    def __init__(self, table_path: str = "./data/null-storage"):
        self.table_path = table_path
        self._logs: List[Dict[str, Any]] = []

    def save_logs(self, logs: List[Dict[str, Any]]):
        self._logs.extend(logs)

    def query_logs(self):
        return list(self._logs)

    def get_history(self):
        return []

    def query_logs_filtered(self, service: Optional[str] = None, start_date: Optional[str] = None, end_date: Optional[str] = None) -> Any:
        return []

    def get_summary(self, service: Optional[str] = None, granularity: str = "hourly", date: Optional[str] = None) -> Dict[str, Any]:
        return {"service": service, "date": date, "hourly_summaries": []}
