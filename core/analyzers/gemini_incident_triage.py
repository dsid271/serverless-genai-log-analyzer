from __future__ import annotations

import os
from typing import Any, Dict


class GeminiIncidentTriageAnalyzer:
    def __init__(self) -> None:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY is required for gemini_triage analyzer")

        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
        except Exception as e:  # pragma: no cover
            raise RuntimeError(
                "langchain_google_genai is not installed; use MODULE_SET=full or install optional deps"
            ) from e

        self._llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash", google_api_key=api_key)

    async def analyze(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        incident = payload.get("incident", {})
        prompt = (
            "You are an on-call SRE assistant.\n"
            "Given the incident payload below, produce: (1) probable root cause hypotheses, "
            "(2) immediate mitigations, (3) next debugging steps, (4) risk/impact note.\n\n"
            f"INCIDENT:\n{incident}\n"
        )

        res = self._llm.invoke(prompt)
        text = getattr(res, "content", str(res))
        return {
            "analyzer": "gemini_triage",
            "triage": text,
        }
