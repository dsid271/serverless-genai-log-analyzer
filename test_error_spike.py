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


def test_shared_trace_id_groups_incidents_across_services(monkeypatch, tmp_path):
    t = _triage(tmp_path, group_window="900", monkeypatch=monkeypatch)
    db, _ = t.raise_incident("error_spike", "spike", {**_details({"orders-db": 8}), "trace_ids": ["t1", "t2"]})
    api, is_new = t.raise_incident("error_spike", "spike", {**_details({"payments-api": 9}), "trace_ids": ["t2", "t3"]})
    other, other_new = t.raise_incident("error_spike", "spike", {**_details({"notif-worker": 6}), "trace_ids": ["t9"]})

    assert not is_new and api.id == db.id
    assert api.details["sources"] == ["orders-db", "payments-api"]
    assert api.details["trace_ids"] == ["t2", "t3", "t1"]
    assert api.routing["team"] == "payments"
    assert other_new and other.id != db.id


def test_detector_and_spark_candidates_carry_trace_ids(monkeypatch, tmp_path):
    from core.connectors.candidates_connector import CandidateHandler

    async def scenario():
        bus, store, det = _make(monkeypatch, tmp_path, cooldown="60", threshold="2")
        await det.start()
        await bus.publish({**_event("a"), "trace_id": "abc"})
        await bus.publish({**_event("b"), "trace_id": "abc"})
        await bus.publish(_event("b"))
        await asyncio.sleep(0.3)
        await det.stop()
        return store.list(limit=10)

    [inc] = asyncio.run(scenario())
    assert inc["details"]["trace_ids"] == ["abc"]

    (tmp_path / "c").mkdir()
    triage = _triage(tmp_path / "c", "0", monkeypatch)
    asyncio.run(CandidateHandler(triage)([{"source": "a", "window_start": "w", "count": 5, "trace_ids": ["x", None]}]))
    assert triage.store.list()[0]["details"]["trace_ids"] == ["x"]


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


def test_spark_candidates_raise_one_incident_per_window(monkeypatch, tmp_path):
    from core.connectors.candidates_connector import CandidateHandler

    triage = _triage(tmp_path, "0", monkeypatch)
    incident_bus = EventBus()
    handler = CandidateHandler(triage, incident_bus)
    cand = {"source": "payments-api", "window_start": "2026-10-11T10:00:00Z", "window_end": "2026-10-11T10:01:00Z",
            "count": 25, "critical_count": 2, "contains_pii": True, "patterns": 3, "sample": "boom", "threshold": 20,
            "baseline": 4.5, "reason": "baseline"}

    async def scenario():
        await handler([cand, {**cand, "count": 40}])           # same window re-sent in update mode
        await handler([{**cand, "window_start": "2026-10-11T10:01:00Z", "source": "orders-db"}])

    asyncio.run(scenario())
    items = triage.store.list(limit=10)
    assert len(items) == 2
    assert incident_bus.queue().qsize() == 2
    first = next(i for i in items if i["details"]["sources"] == ["payments-api"])
    assert first["kind"] == "error_spike" and first["details"]["origin"] == "spark"
    assert first["details"]["count"] == 25 and first["details"]["contains_pii"] is True
    assert first["routing"]["team"] == "payments"
    assert first["details"]["baseline"] == 4.5 and first["details"]["reason"] == "baseline"


def _windows(source, counts, start=0, length=60):
    return [{"source": source, "start": start + i * length, "end": start + (i + 1) * length, "count": c}
            for i, c in enumerate(counts)]


def test_baseline_uses_fixed_threshold_until_warm_then_per_source_average():
    from spark.baseline import SpikeBaseline

    b = SpikeBaseline(threshold=20, factor=3.0, min_count=5, alpha=0.5, warmup=3)
    # Warm-up: only the fixed threshold applies.
    out = b.evaluate(_windows("noisy", [30, 30, 30]) + _windows("quiet", [2, 2, 2]))
    assert [(o["source"], o["reason"]) for o in out] == [("noisy", "threshold")] * 3
    # Warm (the third window closes when the fourth arrives): noisy's 35 is normal, quiet's 12 is a spike.
    out = b.evaluate(_windows("noisy", [35], start=180) + _windows("quiet", [12], start=180))
    assert [(o["source"], o["reason"], o["baseline"]) for o in out] == [("quiet", "baseline", 2.0)]
    assert out[0]["threshold"] == 6.0


def test_baseline_publishes_each_window_once_counts_gaps_and_persists(tmp_path):
    from spark.baseline import SpikeBaseline

    path = str(tmp_path / "baseline.json")
    b = SpikeBaseline(threshold=5, factor=2.0, min_count=3, alpha=0.5, warmup=2, state_path=path)
    assert len(b.evaluate(_windows("api", [6]))) == 1
    assert b.evaluate(_windows("api", [9])) == []                # update mode re-sends the same window
    # 60 is judged on the fixed threshold; by 120, windows 0 (9) and 60 (10) are closed -> warm.
    assert [o["start"] for o in b.evaluate(_windows("api", [10, 10], start=60))] == [60]
    assert b.baseline("api") == 9.5
    assert b.evaluate(_windows("api", [10], start=600)) == []   # 10 < 2 x 9.75
    b.evaluate(_windows("api", [1], start=660))                 # 600 closes after 7 empty windows
    assert b.baseline("api") < 5.1                              # 9.75 decayed by the zeros, then 10 added
    restored = SpikeBaseline(threshold=5, factor=2.0, min_count=3, alpha=0.5, warmup=2, state_path=path)
    assert restored.baseline("api") == b.baseline("api")
    assert restored.evaluate(_windows("api", [50], start=60)) == []    # published before the restart


def test_candidate_payload_shape():
    from spark.streaming_job import candidate_payload

    p = candidate_payload({"source": "a", "start": 1791712800, "end": 1791712860, "count": 7, "critical_count": 1,
                           "pii": 1, "patterns": 2, "sample": "x", "threshold": 6.0, "baseline": 2.0,
                           "reason": "baseline"})
    assert p["window_start"].endswith("Z") and p["contains_pii"] is True and p["reason"] == "baseline"


def test_latency_ms_takes_first_usable_field():
    from spark.transform import latency_ms

    fields = ["duration_ms", "latency_ms", "http_duration_ms"]
    assert latency_ms({"duration_ms": "812.5"}, fields) == 812.5
    assert latency_ms({"duration_ms": True, "latency_ms": -3, "http_duration_ms": 40}, fields) == 40.0
    assert latency_ms({"duration_ms": "slow", "latency_ms": float("nan")}, fields) is None
    assert latency_ms({"message": "no timing"}, fields) is None


def _latency(source, p95s, start=0, length=60, n=50):
    return [{"source": source, "start": start + i * length, "end": start + (i + 1) * length, "n": n, "p95_ms": v}
            for i, v in enumerate(p95s)]


def test_latency_baseline_alerts_on_relative_p95_jump_and_ignores_idle_gaps():
    from spark.baseline import SpikeBaseline
    from spark.streaming_job import select_latency_rows

    b = SpikeBaseline(threshold=1000, factor=2.0, min_count=200, alpha=0.5, warmup=2,
                      value_key="p95_ms", fill_gaps=False)
    # Warm-up: 1200 ms crosses the fixed 1000 ms limit; a 30 -> 90 ms jump does not.
    out = b.evaluate(_latency("checkout", [1200, 1100]) + _latency("search", [30, 30]))
    assert [(o["source"], o["reason"]) for o in out] == [("checkout", "threshold")] * 2
    # A long idle gap must not drag search's p95 baseline toward zero.
    b.evaluate(_latency("search", [30], start=6000))
    assert b.baseline("search") == 30.0
    # Warm: 250 ms is 8x search's baseline and above the 200 ms floor; checkout's 1300 is under 2x 1150.
    out = b.evaluate(_latency("search", [250], start=6060) + _latency("checkout", [1300], start=120))
    assert [(o["source"], o["reason"], o["threshold"]) for o in out] == [("search", "baseline", 200.0)]

    few = _latency("search", [5000], n=3) + [{"source": "x", "start": 0, "end": 60, "n": 99, "p95_ms": None}]
    assert select_latency_rows(few, min_samples=20) == []


def test_latency_candidate_raises_latency_incident_scored_on_p95(monkeypatch, tmp_path):
    from core.connectors.candidates_connector import CandidateHandler
    from spark.streaming_job import latency_payload

    triage = _triage(tmp_path, "900", monkeypatch)
    cand = latency_payload({"source": "payments-api", "start": 1791712800, "end": 1791712860, "n": 120,
                            "p50_ms": 180.0, "p95_ms": 2400.0, "p99_ms": 3100.123, "max_ms": 4000.0,
                            "sample": "GET /pay", "trace_ids": ["t1"], "threshold": 800.0,
                            "baseline": 400.0, "reason": "baseline"})
    error = {"source": "payments-api", "window_start": cand["window_start"], "count": 25, "threshold": 20}

    asyncio.run(CandidateHandler(triage)([cand, cand, error]))
    items = triage.store.list(limit=10)
    assert sorted(i["kind"] for i in items) == ["error_spike", "latency_spike"]
    lat = next(i for i in items if i["kind"] == "latency_spike")
    assert lat["details"]["p95_ms"] == 2400.0 and lat["details"]["p99_ms"] == 3100.12
    assert lat["details"]["baseline_p95_ms"] == 400.0 and lat["details"]["count"] == 120
    assert "p95 2400.0 ms" in lat["message"] and lat["routing"]["team"] == "payments"
    factors = {f["factor"]: f for f in lat["severity"]["factors"]}
    assert "volume" not in factors and factors["latency"]["points"] == 30
