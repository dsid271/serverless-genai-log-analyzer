from typing import Any, Dict

class LogAnalysisEngine:
    def __init__(self, *args: Any, **kwargs: Any):
        pass

    def analyze(self, query: str) -> Dict[str, Any]:
        return {"generation": "Analysis module not enabled.", "query": query, "documents": [], "is_relevant": False}
