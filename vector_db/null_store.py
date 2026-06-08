from typing import List, Dict, Any, Optional

class VectorStore:
    def __init__(self, collection_name: str = "logs"):
        self.collection_name = collection_name
        self._logs: List[Dict[str, Any]] = []

    def add_logs(self, logs: List[Dict[str, Any]]):
        self._logs.extend(logs)

    def search_logs(self, query: str, n_results: int = 5, where_filter: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        matches = self._logs
        if where_filter:
            for k, v in where_filter.items():
                # simple mock filter
                if isinstance(v, list):
                    matches = [l for l in matches if l.get(k) in v]
                else:
                    matches = [l for l in matches if l.get(k) == v]

        if not query:
            return matches[-n_results:]
            
        q = query.lower()
        matches = [l for l in matches if q in str(l.get("message", "")).lower()]
        return matches[:n_results]
