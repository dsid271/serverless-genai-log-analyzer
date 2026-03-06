from __future__ import annotations

import time
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional


@dataclass
class Incident:
    id: str
    created_at: float
    kind: str
    message: str
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["created_at"] = int(self.created_at)
        return d


class IncidentStore:
    def __init__(self, max_items: int = 200) -> None:
        self._max_items = max_items
        self._items: List[Incident] = []
        self._analyses: Dict[str, List[Dict[str, Any]]] = {}

    def add(self, kind: str, message: str, details: Optional[Dict[str, Any]] = None) -> Incident:
        now = time.time()
        inc = Incident(
            id=f"inc-{int(now)}-{len(self._items)+1}",
            created_at=now,
            kind=kind,
            message=message,
            details=details or {},
        )
        self._items.append(inc)
        self._analyses.setdefault(inc.id, [])
        if len(self._items) > self._max_items:
            to_drop = self._items[:-self._max_items]
            self._items = self._items[-self._max_items :]
            for old in to_drop:
                self._analyses.pop(old.id, None)
        return inc

    def attach_analysis(self, incident_id: str, analysis: Dict[str, Any]) -> None:
        if incident_id not in self._analyses:
            self._analyses[incident_id] = []
        self._analyses[incident_id].append(analysis)

    def list(self, limit: int = 50) -> List[Dict[str, Any]]:
        items = self._items[-limit:]
        out: List[Dict[str, Any]] = []
        for i in reversed(items):
            d = i.to_dict()
            d["analyses"] = self._analyses.get(i.id, [])
            out.append(d)
        return out
