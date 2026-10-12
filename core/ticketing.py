"""
External ticketing: PagerDuty (Events API v2), ServiceNow (Table API) and a
generic JSON webhook. Each sink is enabled by its environment variables.

TriageService calls `TicketDispatcher.notify` after every incident change. A
worker thread then, per sink:
- opens a ticket when an open incident reaches TICKET_MIN_SEVERITY,
- updates it when the severity level changes,
- resolves it when the incident is resolved or marked false positive.
Ticket state per incident and provider is kept in the `tickets` table.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import queue
import threading
import urllib.request
from typing import Any, Dict, List, Optional

from core.incident_store import Incident, IncidentStore
from core.severity import LEVELS

logger = logging.getLogger(__name__)


def _team_env(prefix: str, team: Optional[str]) -> Optional[str]:
    """PREFIX_<TEAM> (upper case, '-' -> '_') falling back to PREFIX."""
    if team:
        value = os.getenv(f"{prefix}_{team.upper().replace('-', '_')}")
        if value:
            return value
    return os.getenv(prefix) or None


def _request(method: str, url: str, body: Dict[str, Any], headers: Dict[str, str], timeout: float = 10.0) -> Dict[str, Any]:
    data = json.dumps(body, default=str).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method=method, headers={"Content-Type": "application/json", "Accept": "application/json", **headers}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    return json.loads(raw) if raw else {}


def _summary(inc: Dict[str, Any]) -> str:
    level = (inc.get("severity") or {}).get("level", "unknown")
    team = (inc.get("routing") or {}).get("team", "unassigned")
    return f"[{level}] {inc['message']} (team: {team}, incident {inc['id']})"[:1024]


def _description(inc: Dict[str, Any]) -> str:
    sev, routing, details = inc.get("severity") or {}, inc.get("routing") or {}, inc.get("details") or {}
    lines = [
        inc["message"],
        f"Severity: {sev.get('level')} (score {sev.get('score')})",
        f"Owner: {routing.get('team')} via {routing.get('service')}",
        f"Sources: {', '.join(details.get('sources') or [])}",
        f"Occurrences: {inc.get('occurrences')}",
    ]
    lines += [f"Deployment: {d.get('service')} {d.get('version')}" for d in inc.get("deployments") or []]
    base = os.getenv("TICKET_INCIDENT_URL_BASE")
    if base:
        lines.append(f"Details: {base.rstrip('/')}/{inc['id']}")
    return "\n".join(lines)


class PagerDutySink:
    name = "pagerduty"
    _URL = "https://events.pagerduty.com/v2/enqueue"
    _SEVERITY = {"critical": "critical", "high": "error", "medium": "warning", "low": "info"}

    @staticmethod
    def configured() -> bool:
        return bool(os.getenv("PAGERDUTY_ROUTING_KEY")) or any(k.startswith("PAGERDUTY_ROUTING_KEY_") for k in os.environ)

    def _send(self, action: str, inc: Dict[str, Any]) -> str:
        key = _team_env("PAGERDUTY_ROUTING_KEY", (inc.get("routing") or {}).get("team"))
        if not key:
            raise RuntimeError("no PagerDuty routing key for this team")
        event: Dict[str, Any] = {"routing_key": key, "event_action": action, "dedup_key": inc["id"]}
        if action == "trigger":
            event["payload"] = {
                "summary": _summary(inc),
                "source": (inc.get("routing") or {}).get("service") or "genai-log-analyzer",
                "severity": self._SEVERITY.get((inc.get("severity") or {}).get("level"), "error"),
                "component": ",".join((inc.get("details") or {}).get("sources") or [])[:255],
                "group": (inc.get("routing") or {}).get("team"),
                "class": inc.get("kind"),
                "custom_details": {"description": _description(inc)},
            }
        _request("POST", self._URL, event, {})
        return inc["id"]

    def open(self, inc: Dict[str, Any]) -> str:
        return self._send("trigger", inc)

    def update(self, inc: Dict[str, Any], external_id: str) -> None:
        # Re-triggering with the same dedup_key updates the open PagerDuty incident.
        self._send("trigger", inc)

    def resolve(self, inc: Dict[str, Any], external_id: str) -> None:
        self._send("resolve", inc)


class ServiceNowSink:
    name = "servicenow"
    # (urgency, impact) -> default priority matrix gives P1, P2, P3, P5.
    _PRIORITY = {"critical": ("1", "1"), "high": ("1", "2"), "medium": ("2", "2"), "low": ("3", "3")}

    @staticmethod
    def configured() -> bool:
        return all(os.getenv(k) for k in ("SERVICENOW_INSTANCE", "SERVICENOW_USER", "SERVICENOW_PASSWORD"))

    def _call(self, method: str, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        base = os.environ["SERVICENOW_INSTANCE"].rstrip("/")
        if not base.startswith("http"):
            base = f"https://{base}"
        token = base64.b64encode(f"{os.environ['SERVICENOW_USER']}:{os.environ['SERVICENOW_PASSWORD']}".encode()).decode()
        return _request(method, f"{base}/api/now/table/incident{path}", body, {"Authorization": f"Basic {token}"})

    def _priority(self, inc: Dict[str, Any]) -> Dict[str, str]:
        urgency, impact = self._PRIORITY.get((inc.get("severity") or {}).get("level"), ("2", "2"))
        return {"urgency": urgency, "impact": impact}

    def open(self, inc: Dict[str, Any]) -> str:
        body: Dict[str, Any] = {
            "short_description": _summary(inc)[:160],
            "description": _description(inc),
            "correlation_id": inc["id"],
            **self._priority(inc),
        }
        group = _team_env("SERVICENOW_ASSIGNMENT_GROUP", (inc.get("routing") or {}).get("team"))
        if group:
            body["assignment_group"] = group
        return self._call("POST", "", body)["result"]["sys_id"]

    def update(self, inc: Dict[str, Any], external_id: str) -> None:
        level = (inc.get("severity") or {}).get("level")
        self._call("PATCH", f"/{external_id}", {**self._priority(inc), "work_notes": f"Severity changed to {level}.\n{_description(inc)}"})

    def resolve(self, inc: Dict[str, Any], external_id: str) -> None:
        self._call("PATCH", f"/{external_id}", {
            "state": os.getenv("SERVICENOW_RESOLVED_STATE", "6"),
            "close_code": os.getenv("SERVICENOW_CLOSE_CODE", "Solved (Permanently)"),
            "close_notes": f"Incident {inc['id']} marked {inc.get('status')} in genai-log-analyzer.",
        })


class WebhookSink:
    """POSTs {"event": opened|updated|resolved, "incident": {...}} to TICKET_WEBHOOK_URL.
    With TICKET_WEBHOOK_SECRET set, X-Signature-256 carries an HMAC-SHA256 of the body."""

    name = "webhook"

    @staticmethod
    def configured() -> bool:
        return bool(os.getenv("TICKET_WEBHOOK_URL"))

    def _post(self, event: str, inc: Dict[str, Any]) -> None:
        body = json.dumps({"event": event, "incident": inc}, default=str, sort_keys=True).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        secret = os.getenv("TICKET_WEBHOOK_SECRET")
        if secret:
            headers["X-Signature-256"] = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        req = urllib.request.Request(os.environ["TICKET_WEBHOOK_URL"], data=body, method="POST", headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()

    def open(self, inc: Dict[str, Any]) -> str:
        self._post("opened", inc)
        return inc["id"]

    def update(self, inc: Dict[str, Any], external_id: str) -> None:
        self._post("updated", inc)

    def resolve(self, inc: Dict[str, Any], external_id: str) -> None:
        self._post("resolved", inc)


SINKS = (PagerDutySink, ServiceNowSink, WebhookSink)


class TicketDispatcher:
    def __init__(self, store: IncidentStore, sinks: List[Any], min_level: str = "high") -> None:
        if min_level not in LEVELS:
            raise ValueError(f"TICKET_MIN_SEVERITY must be one of {list(LEVELS)}")
        self.store = store
        self.sinks = sinks
        self.min_level = min_level
        self._queue: "queue.Queue[Optional[Dict[str, Any]]]" = queue.Queue()
        self._thread: Optional[threading.Thread] = None

    @classmethod
    def from_env(cls, store: IncidentStore) -> Optional["TicketDispatcher"]:
        sinks = [sink() for sink in SINKS if sink.configured()]
        if not sinks:
            return None
        return cls(store, sinks, min_level=os.getenv("TICKET_MIN_SEVERITY", "high"))

    def status(self) -> Dict[str, Any]:
        return {
            "providers": [s.name for s in self.sinks],
            "min_severity": self.min_level,
            "queued": self._queue.qsize(),
        }

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, name="ticket-dispatcher", daemon=True)
            self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        if self._thread is not None:
            self._queue.put(None)
            self._thread.join(timeout)
            self._thread = None

    def notify(self, inc: Incident) -> None:
        """Thread-safe; called by TriageService after each save."""
        self._queue.put(inc.to_dict())

    def _run(self) -> None:
        while True:
            inc = self._queue.get()
            if inc is None:
                return
            try:
                self.process(inc)
            except Exception:
                logger.exception("ticket dispatch failed for %s", inc.get("id"))

    def process(self, inc: Dict[str, Any]) -> None:
        state = self.store.tickets(inc["id"])
        level = (inc.get("severity") or {}).get("level")
        is_open = inc.get("status") == "open"
        for sink in self.sinks:
            t = state.get(sink.name)
            ext = t["external_id"] if t else None
            ticket_open = bool(t and t["status"] == "open" and ext)
            try:
                if is_open and not ticket_open:
                    if level in LEVELS and LEVELS.index(level) >= LEVELS.index(self.min_level):
                        ext = sink.open(inc)
                        self.store.save_ticket(inc["id"], sink.name, ext, level, "open")
                elif is_open and t["level"] != level:
                    sink.update(inc, ext)
                    self.store.save_ticket(inc["id"], sink.name, ext, level, "open")
                elif not is_open and ticket_open:
                    sink.resolve(inc, ext)
                    self.store.save_ticket(inc["id"], sink.name, ext, level, "resolved")
            except Exception as e:
                # Keep the previous state so the next incident change retries.
                logger.warning("%s ticket for %s failed: %s", sink.name, inc["id"], e)
                self.store.save_ticket(
                    inc["id"], sink.name, ext, t["level"] if t else None,
                    t["status"] if t else "failed", error=str(e)[:500],
                )
