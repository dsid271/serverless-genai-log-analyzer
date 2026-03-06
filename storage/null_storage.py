from typing import Dict, Any, List

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
