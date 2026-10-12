"""
Incident triage: grouping (noise reduction), severity scoring, ownership
routing, deployment correlation and operator feedback.

Detectors call `raise_incident`; the analyzer runner calls `attach_analysis`.
Resolving an incident with a note indexes it as a postmortem in the knowledge
base, so later triage can retrieve it. Every saved change is passed to
`on_change` (the ticket dispatcher, when configured).
"""

from __future__ import annotations

import logging
import os
import time
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple

from core.incident_store import Incident, IncidentStore
from core.routing import OwnershipMap
from core.severity import LEVELS, score_incident

if TYPE_CHECKING:
    from core.knowledge import KnowledgeBase

logger = logging.getLogger(__name__)

VERDICTS = ("confirmed", "false_positive", "resolved", "reopen")
_VERDICT_STATUS = {"false_positive": "false_positive", "resolved": "resolved", "reopen": "open"}


def _env_int(name: str, default: int) -> int:
    return int(os.getenv(name, str(default)))


class TriageService:
    def __init__(
        self,
        store: IncidentStore,
        ownership: Optional[OwnershipMap] = None,
        knowledge: Optional["KnowledgeBase"] = None,
        on_change: Optional[Callable[[Incident], None]] = None,
    ) -> None:
        self.store = store
        self.ownership = ownership or OwnershipMap()
        self.knowledge = knowledge
        self.on_change = on_change
        # 0 disables grouping: every detector hit becomes a new incident.
        self.group_window = _env_int("INCIDENT_GROUP_WINDOW_SECONDS", 900)
        self.deploy_window = _env_int("DEPLOY_CORRELATION_WINDOW_SECONDS", 1800)

    # --- detector entry point -------------------------------------------

    def raise_incident(self, kind: str, message: str, details: Dict[str, Any]) -> Tuple[Incident, bool]:
        """Create a new incident or fold this hit into a matching open one.
        Returns (incident, is_new)."""
        now = time.time()
        sources = set(details.get("sources") or [])
        match = self._find_group(kind, sources, now)
        if match is None:
            inc = Incident.new(kind, message, details, now=now)
            is_new = True
        else:
            inc = match
            inc.occurrences += 1
            inc.last_seen = now
            inc.message = message
            inc.details = self._merge_details(inc.details, details)
            is_new = False
        self._refresh(inc)
        self._save(inc)
        return inc, is_new

    def _save(self, inc: Incident) -> None:
        self.store.save(inc)
        if self.on_change is not None:
            try:
                self.on_change(inc)
            except Exception:
                logger.exception("on_change hook failed for %s", inc.id)

    def _find_group(self, kind: str, sources: set, now: float) -> Optional[Incident]:
        if self.group_window <= 0:
            return None
        for inc in self.store.find_open(kind=kind, since=now - self.group_window):
            if sources & set(inc.details.get("sources") or []):
                return inc
        return None

    @staticmethod
    def _merge_details(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(new)
        merged["sources"] = sorted(set(old.get("sources") or []) | set(new.get("sources") or []))
        counts = dict(old.get("source_counts") or {})
        for src, n in (new.get("source_counts") or {}).items():
            counts[src] = max(counts.get(src, 0), n)
        merged["source_counts"] = counts
        merged["contains_pii"] = bool(old.get("contains_pii")) or bool(new.get("contains_pii"))
        merged["peak_count"] = max(int(old.get("peak_count") or old.get("count") or 0), int(new.get("count") or 0))
        merged["malicious_ip_count"] = max(
            int(old.get("malicious_ip_count") or 0), int(new.get("malicious_ip_count") or 0)
        )
        return merged

    # --- scoring / routing / correlation --------------------------------

    def _source_counts(self, inc: Incident) -> Dict[str, int]:
        counts = inc.details.get("source_counts")
        if counts:
            return {str(k): int(v) for k, v in counts.items()}
        return {s: 1 for s in inc.details.get("sources") or []}

    def _refresh(self, inc: Incident) -> None:
        services = list(self._source_counts(inc))
        if inc.routing.get("reason") != "manual":
            inc.routing = self.ownership.route(self._source_counts(inc))
        inc.deployments = self.store.deployments_for(
            services, inc.created_at - self.deploy_window, inc.last_seen
        )
        inc.severity = score_incident(
            inc.details,
            occurrences=inc.occurrences,
            tier=self.ownership.tier_for(services),
            deployments=len(inc.deployments),
            llm_severity=inc.severity.get("llm_severity"),
            override=inc.severity.get("override"),
            prior_false_positives=self.store.false_positive_count(
                inc.routing.get("service"), since=time.time() - 7 * 86400, exclude=inc.id
            ),
        )

    def relink_deployment(self, service: str, deployed_at: float) -> List[str]:
        """Re-correlate open incidents after a deployment event arrives late."""
        touched = []
        for inc in self.store.find_open(since=deployed_at - self.deploy_window):
            if service in self._source_counts(inc) and deployed_at <= inc.last_seen:
                self._refresh(inc)
                self._save(inc)
                touched.append(inc.id)
        return touched

    # --- analyzer runner entry point ------------------------------------

    def attach_analysis(self, incident_id: str, analysis: Dict[str, Any]) -> None:
        self.store.attach_analysis(incident_id, analysis)
        llm = analysis.get("severity") if analysis.get("status") == "ok" else None
        if llm is None:
            return
        inc = self.store.get(incident_id)
        if inc is None:
            return
        inc.severity["llm_severity"] = llm
        self._refresh(inc)
        self._save(inc)

    # --- operator feedback ----------------------------------------------

    def apply_feedback(
        self,
        incident_id: str,
        submitted_by: str,
        verdict: Optional[str] = None,
        reassign_team: Optional[str] = None,
        severity_override: Optional[str] = None,
        note: Optional[str] = None,
    ) -> Tuple[Incident, Dict[str, Any]]:
        if verdict is not None and verdict not in VERDICTS:
            raise ValueError(f"verdict must be one of {list(VERDICTS)}")
        if severity_override is not None and severity_override not in LEVELS:
            raise ValueError(f"severity_override must be one of {list(LEVELS)}")
        if reassign_team is not None and not self.ownership.known_team(reassign_team):
            raise ValueError(f"Unknown team '{reassign_team}'")
        if verdict is None and reassign_team is None and severity_override is None and not note:
            raise ValueError("Provide at least one of verdict, reassign_team, severity_override, note")

        inc = self.store.get(incident_id)
        if inc is None:
            raise KeyError(incident_id)

        previous = {"status": inc.status, "team": inc.routing.get("team"), "severity": inc.severity.get("level")}
        if verdict in _VERDICT_STATUS:
            inc.status = _VERDICT_STATUS[verdict]
        if reassign_team is not None:
            inc.routing = {
                **inc.routing,
                "team": reassign_team,
                "reason": "manual",
                "previous_team": previous["team"],
                **self.ownership.contact(reassign_team),
            }
        if severity_override is not None:
            inc.severity["override"] = severity_override

        record = self.store.add_feedback(
            incident_id, submitted_by, verdict, reassign_team, severity_override, note, previous
        )
        self._refresh(inc)
        self._save(inc)
        if verdict == "resolved" and note and self.knowledge is not None:
            record["postmortem_id"] = self._index_postmortem(inc, note)["id"]
        return inc, record

    def _index_postmortem(self, inc: Incident, note: str) -> Dict[str, Any]:
        services = list(self._source_counts(inc))
        deploys = ", ".join(f"{d['service']} {d['version']}" for d in inc.deployments) or "none"
        content = (
            f"Incident {inc.id} ({inc.kind}) on {', '.join(services)}.\n"
            f"Summary: {inc.message}\n"
            f"Severity: {inc.severity.get('level')}; owner: {inc.routing.get('team')}; "
            f"occurrences: {inc.occurrences}; linked deployments: {deploys}.\n"
            f"Resolution: {note}"
        )
        return self.knowledge.add(
            "postmortem", f"Postmortem {inc.id}: {inc.message}", content, services=services, doc_id=f"pm-{inc.id}"
        )
