import asyncio

import pytest

from core.detectors.error_spike import ErrorSpikeDetector
from core.event_bus import EventBus
from core.incident_store import IncidentStore
from core.routing import OwnershipMap
from core.triage import TriageService

_OWNERSHIP = """
default_team: platform-oncall
teams:
  payments:
    services: ["payments-*"]
    tier: 1
    oncall: pay@example.com
  data:
    services: ["*-db"]
    tier: 2
"""


def _event(source: str, pii: bool = False, severity: str = "ERROR") -> dict:
    return {"severity": severity, "message": "boom", "source": source, "contains_pii": pii}


def _triage(tmp_path, group_window: str = "0", monkeypatch=None) -> TriageService:
    if monkeypatch is not None:
        monkeypatch.setenv("INCIDENT_GROUP_WINDOW_SECONDS", group_window)
    own = tmp_path / "ownership.yaml"
    own.write_text(_OWNERSHIP, encoding="utf-8")
    return TriageService(IncidentStore(str(tmp_path / "incidents.sqlite3")), OwnershipMap(str(own)))


def _make(monkeypatch, tmp_path, cooldown: str, threshold: str = "2", group_window: str = "0"):
    monkeypatch.setenv("ERROR_SPIKE_THRESHOLD", threshold)
    monkeypatch.setenv("ERROR_SPIKE_WINDOW_SECONDS", "60")
    monkeypatch.setenv("ERROR_SPIKE_COOLDOWN_SECONDS", cooldown)
    triage = _triage(tmp_path, group_window, monkeypatch)
    bus = EventBus()
    return bus, triage.store, ErrorSpikeDetector(bus, triage, EventBus())


def test_detector_survives_multiple_incidents(monkeypatch, tmp_path):
    """Regression: the detector task used to die after its first incident."""

    async def scenario():
        bus, store, det = _make(monkeypatch, tmp_path, cooldown="1")
        await det.start()
        await bus.publish(_event("a"))
        await bus.publish(_event("b", pii=True))
        await asyncio.sleep(0.3)
        first = len(store.list(limit=10))

        await asyncio.sleep(1.2)  # let the cooldown expire
        await bus.publish(_event("a"))
        await asyncio.sleep(0.3)
        items = store.list(limit=10)
        alive = not det._task.done()
        await det.stop()
        return first, items, alive

    first, items, alive = asyncio.run(scenario())
    assert first == 1
    assert len(items) == 2
    assert alive
    latest = items[0]["details"]  # newest first
    assert latest["count"] == 3  # window is not cleared when an incident fires
    assert latest["contains_pii"] is True  # aggregated over the window
    assert latest["sources"] == ["a", "b"]


def test_cooldown_suppresses_duplicates_and_ignores_non_errors(monkeypatch, tmp_path):
    async def scenario():
        bus, store, det = _make(monkeypatch, tmp_path, cooldown="60")
        await det.start()
        await bus.publish(_event("a", severity="INFO"))  # ignored
        for _ in range(5):
            await bus.publish(_event("a"))
        await asyncio.sleep(0.3)
        count = len(store.list(limit=10))
        await det.stop()
        return count

    assert asyncio.run(scenario()) == 1


def _details(counts: dict, count: int = 10, threshold: int = 5, critical: int = 0) -> dict:
    return {
        "count": count, "threshold": threshold, "critical_count": critical,
        "sources": sorted(counts), "source_counts": counts,
    }


def test_grouping_folds_overlapping_hits_into_one_incident(monkeypatch, tmp_path):
    t = _triage(tmp_path, group_window="900", monkeypatch=monkeypatch)
    first, new1 = t.raise_incident("error_spike", "spike", _details({"payments-api": 8}))
    second, new2 = t.raise_incident("error_spike", "spike", _details({"payments-api": 9, "orders-db": 3}))
    other, new3 = t.raise_incident("error_spike", "spike", _details({"notif-worker": 6}))

    assert (new1, new2, new3) == (True, False, True)
    assert second.id == first.id and second.occurrences == 2
    assert second.details["sources"] == ["orders-db", "payments-api"]
    assert other.id != first.id
    assert len(t.store.list()) == 2


def test_routing_and_severity_factors(monkeypatch, tmp_path):
    t = _triage(tmp_path, monkeypatch=monkeypatch)
    inc, _ = t.raise_incident("error_spike", "spike", _details({"orders-db": 2, "payments-api": 8}, critical=1))
    assert inc.routing["team"] == "payments"
    assert inc.routing["also_affected"] == ["data"]
    assert inc.routing["oncall"] == "pay@example.com"
    factors = {f["factor"] for f in inc.severity["factors"]}
    assert {"volume", "critical_logs", "blast_radius", "service_tier"} <= factors
    assert inc.severity["level"] in {"high", "critical"}

    unowned, _ = t.raise_incident("error_spike", "spike", _details({"mystery-svc": 5}))
    assert unowned.routing["team"] == "platform-oncall"
    assert unowned.routing["reason"] == "default_team"


def test_deployment_is_correlated_even_when_it_arrives_late(monkeypatch, tmp_path):
    import time

    t = _triage(tmp_path, monkeypatch=monkeypatch)
    inc, _ = t.raise_incident("error_spike", "spike", _details({"payments-api": 8}))
    assert inc.deployments == []
    t.store.add_deployment("payments-api", "v2.3.1", "production", time.time() - 120)
    assert t.relink_deployment("payments-api", time.time() - 120) == [inc.id]
    refreshed = t.store.get(inc.id)
    assert refreshed.deployments[0]["version"] == "v2.3.1"
    assert "recent_deploy" in {f["factor"] for f in refreshed.severity["factors"]}


def test_feedback_override_reroute_and_false_positive_damping(monkeypatch, tmp_path):
    t = _triage(tmp_path, monkeypatch=monkeypatch)
    inc, _ = t.raise_incident("error_spike", "spike", _details({"payments-api": 8}))

    inc, rec = t.apply_feedback(inc.id, "alice", reassign_team="data", severity_override="low")
    assert inc.routing["team"] == "data" and inc.routing["reason"] == "manual"
    assert inc.severity["level"] == "low" and inc.severity["override"] == "low"
    assert rec["previous"]["team"] == "payments"

    # Manual routing and the override survive re-scoring when an LLM analysis arrives.
    t.attach_analysis(inc.id, {"status": "ok", "severity": "high"})
    after = t.store.get(inc.id)
    assert after.routing["team"] == "data" and after.severity["level"] == "low"
    assert after.severity["llm_severity"] == "high"

    inc, _ = t.apply_feedback(inc.id, "alice", verdict="false_positive")
    assert inc.status == "false_positive"
    assert t.store.find_open() == []

    nxt, _ = t.raise_incident("error_spike", "spike", _details({"payments-api": 8}))
    damp = [f for f in nxt.severity["factors"] if f["factor"] == "prior_false_positives"]
    assert damp and damp[0]["points"] < 0

    with pytest.raises(ValueError):
        t.apply_feedback(nxt.id, "alice", reassign_team="no-such-team")
    with pytest.raises(KeyError):
        t.apply_feedback("inc-missing", "alice", verdict="resolved")
