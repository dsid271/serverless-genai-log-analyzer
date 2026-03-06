from __future__ import annotations

from typing import Any, Dict


class SimpleIncidentSummaryAnalyzer:
    async def analyze(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        incident = payload.get("incident", {})
        kind = incident.get("kind", "unknown")
        message = incident.get("message", "")
        details = incident.get("details", {})

        summary = f"Incident kind: {kind}. {message}".strip()
        return {
            "analyzer": "simple_summary",
            "summary": summary,
            "details": details,
        }
