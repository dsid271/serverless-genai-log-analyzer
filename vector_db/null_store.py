from typing import List, Dict, Any

class VectorStore:
    def __init__(self, collection_name: str = "logs"):
        self.collection_name = collection_name
        self._logs: List[Dict[str, Any]] = []

    def add_logs(self, logs: List[Dict[str, Any]]):
        self._logs.extend(logs)

    def search_logs(self, query: str, n_results: int = 5) -> List[Dict[str, Any]]:
        if not query:
            return self._logs[-n_results:]
        q = query.lower()
        matches = [l for l in self._logs if q in str(l.get("message", "")).lower()]
        return matches[:n_results]
