from fastapi.testclient import TestClient
from api.main import app


def test_api_ingest_search_summary_audit(monkeypatch):
    # Ensure auth is disabled and the detector/analyzer pipeline is enabled for the test
    monkeypatch.setenv("ENABLE_AUTH", "false")
    monkeypatch.setenv("ENABLED_DETECTORS", "error_spike")
    monkeypatch.setenv("ERROR_SPIKE_THRESHOLD", "1")
    monkeypatch.setenv("ERROR_SPIKE_WINDOW_SECONDS", "60")
    monkeypatch.setenv("ERROR_SPIKE_COOLDOWN_SECONDS", "0")
    monkeypatch.setenv("ENABLED_ANALYZERS", "simple_summary")
    monkeypatch.setenv("GEMINI_API_KEY", "")

    with TestClient(app) as client:
        ingest_payload = {
            "logs": [
                {
                    "timestamp": "2026-08-01T12:00:00Z",
                    "severity": "ERROR",
                    "source": "test-service",
                    "message": "Test error for endpoint coverage from john.doe@example.com",
                    "customer_id": "8827361",
                    "source_ip": "203.0.113.10",
                    "request_id": "req-test-0001",
                    "traceId": "4bf92f3577b34da6a3ce929d0e0e4736"
                }
            ]
        }

        response = client.post("/ingest", json=ingest_payload)
        assert response.status_code == 200, response.text
        data = response.json()
        assert data["status"] == "success"
        assert data["count"] == 1
        assert data["contains_pii"] is True

        incidents_response = client.get("/incidents")
        assert incidents_response.status_code == 200, incidents_response.text
        incidents = incidents_response.json().get("incidents", [])
        assert isinstance(incidents, list)
        assert len(incidents) >= 1
        assert any(incident.get("details", {}).get("contains_pii") is True for incident in incidents)

        # Change event, feedback loop and knowledge base.
        inc = next(i for i in incidents if "test-service" in i["details"]["sources"])
        assert inc["status"] == "open" and inc["severity"]["factors"] and inc["routing"]["team"]
        from datetime import datetime, timedelta, timezone
        deployed_at = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
        dep = client.post(
            "/events/deployments",
            json={"service": "test-service", "version": "v9.9.9", "deployed_at": deployed_at},
        )
        assert dep.status_code == 201, dep.text
        assert inc["id"] in dep.json()["linked_incidents"]

        bad = client.post(f"/incidents/{inc['id']}/feedback", json={"verdict": "maybe"})
        assert bad.status_code == 422
        fb = client.post(
            f"/incidents/{inc['id']}/feedback",
            json={"verdict": "resolved", "note": "Rolled back test-service v9.9.9; bad DB pool size."},
        )
        assert fb.status_code == 200, fb.text
        assert fb.json()["incident"]["status"] == "resolved"
        pm_id = fb.json()["feedback"]["postmortem_id"]

        detail = client.get(f"/incidents/{inc['id']}").json()
        assert detail["deployments"][0]["version"] == "v9.9.9"
        assert detail["feedback"][0]["verdict"] == "resolved"
        hits = client.get("/knowledge", params={"q": "test-service DB pool rollback"}).json()["documents"]
        assert pm_id in {h["id"] for h in hits}
        assert client.delete(f"/knowledge/{pm_id}").status_code == 200
        assert client.get("/incidents/inc-missing").status_code == 404

        search_payload = {"query": "endpoint coverage for jane.roe@example.com", "limit": 1}
        search_response = client.post("/search", json=search_payload)
        assert search_response.status_code == 200, search_response.text
        search_json = search_response.json()
        assert "results" in search_json
        assert isinstance(search_json["results"], list)

        # The trace id survives redaction and is stored under the canonical name.
        traced = client.post("/query", json={"filters": {"trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"}})
        assert traced.status_code == 200, traced.text
        assert traced.json()["total"] >= 1
        assert "4bf92f3577b34da6a3ce929d0e0e4736" in inc["details"]["trace_ids"]

        summary_response = client.get("/summary")
        assert summary_response.status_code == 200, summary_response.text
        assert "hourly_summaries" in summary_response.json()

        audit_response = client.get("/audit-trail")
        assert audit_response.status_code == 200, audit_response.text
        events = audit_response.json().get("events", [])
        assert "events" in audit_response.json()
        assert any(
            event.get("action") == "POST /ingest" and event.get("contains_pii") is True
            for event in events
        )

        # /search records what was asked (redacted) and how many results came back.
        search_events = [e for e in events if e.get("action") == "POST /search" and "endpoint coverage" in (e.get("detail") or "")]
        assert search_events, "POST /search content missing from the audit trail"
        assert "jane.roe@example.com" not in search_events[0]["detail"]
        assert search_events[0]["results_count"] == search_json["count"]

        summary = summary_response.json()["hourly_summaries"]
        bucket = next(b for b in summary if b["hour"] == "2026-08-01T12:00:00Z")
        assert bucket["error_count"] >= 1


def test_key_issuance_scopes_expiry_and_revocation(monkeypatch, tmp_path):
    import time
    from api.key_store import KeyStore, get_key_store

    monkeypatch.setenv("API_KEYS_DB", str(tmp_path / "keys.sqlite3"))
    monkeypatch.setenv("ENABLE_AUTH", "true")
    admin_key, _ = get_key_store().issue("bootstrap-admin", "admin")

    # No lifespan needed: auth does not depend on connectors/detectors.
    client = TestClient(app)
    assert client.get("/incidents").status_code == 401
    assert client.get("/incidents", headers={"X-API-Key": "gla_nope_nope"}).status_code == 401

    admin = {"X-API-Key": admin_key}
    issued = client.post("/admin/keys", headers=admin, json={"name": "shipper", "profile": "ingest-service"})
    assert issued.status_code == 201, issued.text
    body = issued.json()
    assert body["scopes"] == ["logs:ingest"]
    assert body["issued_by"] == f"bootstrap-admin:{admin_key.split('_')[1]}"
    ingest_only = {"X-API-Key": body["api_key"]}

    # Scope enforcement: ingest-service can ingest but cannot read incidents.
    assert client.get("/incidents", headers=ingest_only).status_code == 403
    hook = client.post("/admin/keys", headers=admin, json={"name": "ci", "profile": "deploy-webhook"}).json()
    hook_hdr = {"X-API-Key": hook["api_key"]}
    assert client.post("/incidents/x/feedback", headers=hook_hdr, json={"note": "n"}).status_code == 403
    assert client.post("/knowledge", headers=hook_hdr, json={}).status_code == 403
    bad_profile = client.post("/admin/keys", headers=admin, json={"name": "x", "profile": "root"})
    assert bad_profile.status_code == 400

    listed = client.get("/admin/keys", headers=admin).json()["keys"]
    assert {k["key_id"] for k in listed} >= {body["key_id"]}
    assert all("api_key" not in k and "secret_hash" not in k for k in listed)

    assert client.delete(f"/admin/keys/{body['key_id']}", headers=admin).status_code == 200
    assert client.get("/plugins", headers=ingest_only).status_code == 401
    assert client.delete(f"/admin/keys/{body['key_id']}", headers=admin).status_code == 404

    # With auth off every caller is anonymous; it must not be able to mint keys.
    monkeypatch.setenv("ENABLE_AUTH", "false")
    anon = client.post("/admin/keys", json={"name": "sneaky", "profile": "admin"})
    assert anon.status_code == 403
    assert "sneaky" not in {k.name for k in get_key_store().list()}
    monkeypatch.setenv("ENABLE_AUTH", "true")

    store = KeyStore(str(tmp_path / "expiry.sqlite3"))
    raw, rec = store.issue("short-lived", "viewer", ttl_days=1)
    assert store.verify(raw) is not None
    monkeypatch.setattr(time, "time", lambda: rec.expires_at + 1)
    assert store.verify(raw) is None


def test_pii_rule_review_endpoints(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from api.key_store import get_key_store
    from api.main import orchestrator
    from processing.pii_rules import PiiRuleStore

    store = PiiRuleStore(str(tmp_path / "rules.sqlite3"), b"k", entities=["PERSON"], min_distinct=2)
    for name in ("Maria Gonzalez", "John Smith"):
        text = f"refund denied for {name}"
        start = text.index(name)
        store.observe(text, [SimpleNamespace(entity_type="PERSON", start=start, end=start + len(name))])
    monkeypatch.setattr(orchestrator.enricher.redactor, "pii_rules", store)
    monkeypatch.setenv("API_KEYS_DB", str(tmp_path / "keys.sqlite3"))
    monkeypatch.setenv("ENABLE_AUTH", "true")
    admin = {"X-API-Key": get_key_store().issue("admin", "admin")[0]}
    analyst = {"X-API-Key": get_key_store().issue("analyst", "analyst")[0]}

    client = TestClient(app)
    assert client.get("/admin/pii-rules", headers=analyst).status_code == 403
    listed = client.get("/admin/pii-rules", headers=admin)
    assert listed.status_code == 200, listed.text
    [rule] = listed.json()["rules"]
    assert rule["display"] == "refund denied for {PERSON}" and listed.json()["counts"]["pending"] == 1
    assert client.get("/admin/pii-rules?status=bogus", headers=admin).status_code == 400

    body = {"ids": [rule["id"], "missing"], "status": "approved"}
    decided = client.post("/admin/pii-rules/decisions", headers=admin, json=body)
    assert decided.status_code == 200, decided.text
    assert decided.json()["updated"][0]["status"] == "approved" and decided.json()["not_found"] == ["missing"]
    assert decided.json()["updated"][0]["decided_by"].startswith("admin:")
    bad = client.post("/admin/pii-rules/decisions", headers=admin, json={"ids": [rule["id"]], "status": "x"})
    assert bad.status_code == 422
    assert store.apply("Refund denied for Zed Quux") == ("Refund denied for [REDACTED]", True)

    # Learned entities use the same review endpoints; off unless PII_LEARNING is on.
    monkeypatch.setattr(orchestrator.enricher.redactor, "learned", None)
    assert client.get("/admin/pii-rules?kind=entity", headers=admin).status_code == 503
    from processing.learned_pii import LearnedEntities
    learned = LearnedEntities(str(tmp_path / "learned.sqlite3"), b"k", entities=["PERSON"], min_hits=1,
                              reload_seconds=0)
    hit = SimpleNamespace(entity_type="PERSON", start=0, end=14)
    learned.observe("Maria Gonzalez", [hit])
    monkeypatch.setattr(orchestrator.enricher.redactor, "learned", learned)
    [entity] = client.get("/admin/pii-rules?kind=entity", headers=admin).json()["rules"]
    assert entity["kind"] == "entity" and "maria" not in entity["display"].lower()
    assert learned.apply("Maria Gonzalez")[1] is False
    done = client.post("/admin/pii-rules/decisions", headers=admin, json={"ids": [entity["id"]], "status": "approved"})
    assert done.json()["updated"][0]["status"] == "approved" and done.json()["not_found"] == []
    assert learned.apply("Maria Gonzalez") == ("[REDACTED]", True)

    assert "text/html" in client.get("/ui/pii-rules").headers["content-type"]
    metrics = client.get("/metrics").text
    if "disabled" not in metrics:
        assert 'pii_rule_suggestions{status="approved"} 1.0' in metrics


def test_ticket_dispatcher_open_update_resolve_and_retry(tmp_path):
    from core.incident_store import IncidentStore
    from core.ticketing import TicketDispatcher

    class FakeSink:
        name = "fake"

        def __init__(self):
            self.calls, self.fail = [], False

        def _rec(self, action, inc):
            if self.fail:
                raise RuntimeError("provider down")
            self.calls.append((action, inc["severity"]["level"]))

        def open(self, inc):
            self._rec("open", inc)
            return "EXT-1"

        def update(self, inc, external_id):
            self._rec("update", inc)

        def resolve(self, inc, external_id):
            self._rec("resolve", inc)

    store = IncidentStore(str(tmp_path / "inc.sqlite3"))
    sink = FakeSink()
    d = TicketDispatcher(store, [sink], min_level="high")
    inc = {"id": "inc-1", "status": "open", "message": "m", "severity": {"level": "medium"}}

    d.process(inc)  # below threshold
    assert sink.calls == [] and store.tickets("inc-1") == {}

    sink.fail = True
    d.process({**inc, "severity": {"level": "high"}})
    assert store.tickets("inc-1")["fake"]["status"] == "failed"
    sink.fail = False
    d.process({**inc, "severity": {"level": "high"}})  # retried
    d.process({**inc, "severity": {"level": "high"}})  # unchanged: no call
    d.process({**inc, "severity": {"level": "critical"}})
    d.process({**inc, "status": "resolved", "severity": {"level": "critical"}})
    d.process({**inc, "status": "resolved", "severity": {"level": "critical"}})
    assert sink.calls == [("open", "high"), ("update", "critical"), ("resolve", "critical")]
    t = store.tickets("inc-1")["fake"]
    assert t["external_id"] == "EXT-1" and t["status"] == "resolved"


def test_webhook_sink_signs_body(monkeypatch):
    import hashlib
    import hmac
    import json
    import core.ticketing as ticketing

    sent = {}

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b""

    def fake_urlopen(req, timeout):
        sent["body"], sent["sig"] = req.data, req.get_header("X-signature-256")
        return Resp()

    monkeypatch.setenv("TICKET_WEBHOOK_URL", "http://hooks.invalid/x")
    monkeypatch.setenv("TICKET_WEBHOOK_SECRET", "s3")
    monkeypatch.setattr(ticketing.urllib.request, "urlopen", fake_urlopen)
    assert ticketing.WebhookSink().open({"id": "inc-9", "message": "m"}) == "inc-9"
    assert json.loads(sent["body"])["event"] == "opened"
    assert sent["sig"] == "sha256=" + hmac.new(b"s3", sent["body"], hashlib.sha256).hexdigest()


def test_ip_enrichment_adds_flat_fields_for_public_ips_only():
    from processing.enricher import LogEnricher

    class Redactor:
        def redact_log(self, log):
            return {**log, "source_ip": "<redacted>"}

    class FakeIntel:
        def __init__(self):
            self.batches = []

        def lookup_many(self, ips):
            ips = sorted(set(ips))
            self.batches.append(ips)
            return {ip: {"country": "NL", "abuse_score": 90, "malicious": True} for ip in ips}

        def lookup(self, ip):
            raise AssertionError("batch path must not do per-log lookups")

    intel = FakeIntel()
    out = LogEnricher(redactor=Redactor(), ip_intel=intel).process_logs([
        {"source_ip": "8.8.8.8"}, {"source_ip": "8.8.8.8"}, {"source_ip": "10.0.0.5"},
    ])
    assert intel.batches == [["8.8.8.8"]]
    assert out[0]["source_ip_country"] == "NL" and out[0]["source_ip_malicious"] is True
    assert out[0]["source_ip_scope"] == "public" and out[0]["source_ip"] == "<redacted>"
    assert out[2]["source_ip_scope"] == "private" and "source_ip_country" not in out[2]


def test_pattern_sampler_keeps_one_example_per_pattern_until_ttl():
    from processing.log_pattern import PatternSampler, message_pattern

    assert message_pattern("timeout after 350ms on 10.0.0.7 req 3f2a9b7c1d") == \
        message_pattern("timeout after 12ms on 10.0.0.9 req aa11bb22cc")

    now = [0.0]
    sampler = PatternSampler(ttl_seconds=60, clock=lambda: now[0])
    base = {"source": "billing", "severity": "ERROR"}
    batch = [
        {**base, "message": "timeout after 350ms"},
        {**base, "message": "timeout after 12ms"},
        {**base, "message": "disk full"},
        {"source": "other", "severity": "ERROR", "message": "timeout after 5ms"},
    ]
    picked = sampler.select(batch)
    assert [p["message"] for p in picked] == ["timeout after 350ms", "disk full", "timeout after 5ms"]
    assert all(p["pattern_id"] for p in picked)
    assert "pattern_id" not in batch[0]          # inputs are not modified

    assert sampler.select(batch) == []
    now[0] = 61.0
    assert len(sampler.select(batch)) == 3        # TTL expired: refreshed


def test_orchestrator_embeds_patterns_only_and_all_mode_embeds_everything(monkeypatch):
    import asyncio
    from api.orchestrator import SystemOrchestrator

    class Enricher:
        def process_logs(self, logs):
            return [dict(log) for log in logs]

    class Store:
        def save_logs(self, logs):
            pass

    class Vectors:
        def __init__(self):
            self.docs = []

        def add_logs(self, logs):
            self.docs.extend(logs)

    logs = [{"source": "s", "severity": "ERROR", "message": f"timeout after {n}ms"} for n in range(5)]

    async def run(mode):
        monkeypatch.setenv("VECTOR_INDEX_MODE", mode)
        vectors = Vectors()
        orch = SystemOrchestrator(Enricher(), Store(), vectors, engine=None)
        await orch.ingest_logs(logs)
        await asyncio.gather(*orch._index_tasks)
        return vectors.docs

    assert len(asyncio.run(run("pattern"))) == 1
    assert len(asyncio.run(run("all"))) == 5


def _lake(tmp_path):
    """API table plus a Spark-shaped table (fixed columns; other fields only inside `record`)."""
    import json
    import pandas as pd
    from deltalake import write_deltalake
    from storage.lake import DeltaLakeStorage

    spark_path = str(tmp_path / "logs_stream")
    rows = [{"timestamp": f"2026-08-01T12:0{i}:00Z", "source": "payments-api", "severity": "ERROR",
             "record": json.dumps({"status_code": 500, "customer_id": c})} for i, c in enumerate(["c1", "c1", "c2"])]
    write_deltalake(spark_path, pd.DataFrame(rows))
    lake = DeltaLakeStorage(str(tmp_path / "logs"), read_paths=[spark_path, str(tmp_path / "missing")])
    lake.save_logs([
        {"timestamp": "2026-08-01T12:05:00Z", "source": "payments-api", "severity": "ERROR", "status_code": 500, "customer_id": "c2"},
        {"timestamp": "2026-08-01T12:06:00Z", "source": "payments-api", "severity": "INFO", "status_code": 200, "customer_id": "c1"},
        {"timestamp": "2026-08-01T12:07:00Z", "source": "auth", "severity": "ERROR", "customer_id": "c3"},
    ])
    return lake


def test_lake_aggregate_counts_across_api_and_spark_tables(tmp_path):
    import pandas as pd

    lake = _lake(tmp_path)
    out = lake.aggregate(filters={"status_code": 500}, group_by=["customer_id"])
    assert out["rows"] == [{"customer_id": "c1", "count": 2}, {"customer_id": "c2", "count": 2}]
    assert out["total"] == 4 and out["scanned"] == 6

    window = lake.aggregate(filters={"status_code": ["500", "200"]}, group_by=["source", "status_code"],
                            start=pd.Timestamp("2026-08-01T12:02:00Z"), end=pd.Timestamp("2026-08-01T12:06:00Z"))
    assert window["rows"] == [{"source": "payments-api", "status_code": "500", "count": 2},
                              {"source": "payments-api", "status_code": "200", "count": 1}]
    nulls = lake.aggregate(group_by=["status_code"], limit=5)["rows"]
    assert {"status_code": None, "count": 1} in nulls
    assert lake.aggregate()["rows"] == [{"count": 6}]
    hours = lake.get_summary(service="payments-api")["hourly_summaries"]
    assert hours == [{"hour": "2026-08-01T12:00:00Z", "total_logs": 5, "error_count": 4, "error_rate": 0.8}]


def _latency_lake(tmp_path):
    import json
    import pandas as pd
    from deltalake import write_deltalake
    from storage.lake import DeltaLakeStorage

    spark_path = str(tmp_path / "logs_stream")   # duration only inside the record JSON
    write_deltalake(spark_path, pd.DataFrame([{
        "timestamp": "2026-08-01T12:05:00Z", "source": "payments-api", "severity": "INFO",
        "record": json.dumps({"duration_ms": 500})}]))
    lake = DeltaLakeStorage(str(tmp_path / "logs"), read_paths=[spark_path])
    rows = [{"timestamp": f"2026-08-01T12:0{i}:00Z", "source": "payments-api", "severity": "INFO", "duration_ms": d}
            for i, d in enumerate([100, 200, 300, 400, 1000])]
    lake.save_logs(rows + [{"timestamp": "2026-08-01T12:06:00Z", "source": "auth", "severity": "INFO"}])
    return lake


def test_lake_aggregate_latency_percentiles(tmp_path):
    import pandas as pd

    lake = _latency_lake(tmp_path)
    by_source = {r["source"]: r for r in lake.aggregate(group_by=["source"], metric="duration_ms")["rows"]}
    pay = by_source["payments-api"]
    # Values 100,200,300,400,500,1000 (500 comes from the Spark table's record column).
    assert pay["count"] == 6
    assert pay["metric"] == {"field": "duration_ms", "n": 6, "avg": 416.667, "p50": 350.0,
                             "p95": 875.0, "p99": 975.0, "max": 1000.0}
    assert by_source["auth"]["count"] == 1 and by_source["auth"]["metric"]["n"] == 0
    assert by_source["auth"]["metric"]["p95"] is None

    total = lake.aggregate(metric="duration_ms")["rows"][0]
    assert total["count"] == 7 and total["metric"]["n"] == 6
    window = lake.aggregate(filters={"source": "payments-api"}, metric="duration_ms",
                            end=pd.Timestamp("2026-08-01T12:01:00Z"))["rows"][0]
    assert window["metric"]["n"] == 2 and window["metric"]["p50"] == 150.0
    assert lake.aggregate(filters={"source": "nobody"}, metric="duration_ms")["rows"][0]["metric"]["n"] == 0
    assert "metric" not in lake.aggregate(group_by=["source"])["rows"][0]
    assert lake.aggregate(metric="not_a_field")["rows"][0]["metric"]["n"] == 0


def test_query_endpoint_returns_percentiles_and_validates_metric(monkeypatch, tmp_path):
    from api.main import orchestrator

    monkeypatch.setenv("ENABLE_AUTH", "false")
    monkeypatch.setattr(orchestrator, "storage", _latency_lake(tmp_path))
    client = TestClient(app)
    ok = client.post("/query", json={"metric": "duration_ms", "group_by": ["source"]})
    assert ok.status_code == 200, ok.text
    assert ok.json()["rows"][0]["metric"]["p95"] == 875.0
    assert client.post("/query", json={"metric": "bad field;"}).status_code == 400


def test_query_endpoint_validates_and_aggregates(monkeypatch, tmp_path):
    from api.main import orchestrator

    monkeypatch.setenv("ENABLE_AUTH", "false")
    monkeypatch.setattr(orchestrator, "storage", _lake(tmp_path))
    client = TestClient(app)
    ok = client.post("/query", json={"filters": {"status_code": 500}, "group_by": ["customer_id"],
                                     "start": "2026-08-01T12:00:00Z", "end": "2026-08-01T12:04:00"})
    assert ok.status_code == 200, ok.text
    assert ok.json()["rows"] == [{"customer_id": "c1", "count": 2}, {"customer_id": "c2", "count": 1}]
    assert client.post("/query", json={"last_minutes": 15}).json()["total"] == 0
    assert client.post("/query", json={"group_by": ["bad field;"]}).status_code == 400
    assert client.post("/query", json={"last_minutes": 5, "start": "2026-08-01T12:00:00Z"}).status_code == 400
    assert client.post("/query", json={"limit": 0}).status_code == 422


def test_triage_eval_grader():
    from scripts.eval_triage import grade, summarize

    titles = ["Payments DB connection pool exhaustion", "Log volume disk full"]
    case = {"name": "pool", "expected_docs": [titles[0]], "severity": ["high"], "keywords": ["roll back|rollback", "pool"]}
    good = {"status": "ok", "severity": "high", "hypotheses": ["DB pool too small after v2.4.0"],
            "mitigations": ["Roll back payments-api"], "next_steps": ["Follow 'Payments DB connection-pool exhaustion'"],
            "impact": "checkout fails", "references": [{"title": titles[0]}]}
    assert grade(case, good, titles)["passed"]

    misuse = {**good, "next_steps": ["See Log volume disk full", "Payments DB connection pool exhaustion"]}
    r = grade(case, misuse, titles)
    assert not r["checks"]["no_misuse"] and r["checks"]["cited"] and r["named"] == titles
    r = grade(case, {**good, "severity": "low", "mitigations": ["restart"], "references": []}, titles)
    assert {c for c, v in r["checks"].items() if not v} == {"retrieved", "severity", "keywords"}
    assert r["missing_keywords"] == ["roll back|rollback"]

    none_case = {"name": "none", "expected_docs": []}
    assert grade(none_case, {**good, "next_steps": ["check image decoder"]}, titles)["passed"]
    assert not grade(none_case, good, titles)["checks"]["cited"]
    failed = grade(case, {"status": "failed", "detail": "quota"}, titles)
    assert not failed["passed"] and failed["error"] == "quota"
    assert summarize([failed, grade(case, good, titles)])["pass_rate"] == 0.5



# --- backup script ---------------------------------------------------------------------------

def test_backup_snapshots_a_live_wal_database_and_copies_delta_log_last(tmp_path):
    import sqlite3
    from scripts.backup import LOG_ONLY, NO_LOG, plan, sqlite_snapshot

    src = tmp_path / "live.sqlite3"
    live = sqlite3.connect(src)
    live.execute("PRAGMA journal_mode=WAL")
    live.execute("CREATE TABLE t (n INTEGER)")
    live.executemany("INSERT INTO t VALUES (?)", [(i,) for i in range(100)])
    live.commit()
    live.execute("INSERT INTO t VALUES (999)")          # uncommitted write on the open connection
    sqlite_snapshot(str(src), str(tmp_path / "snap.sqlite3"))
    live.rollback()
    live.close()
    snap = sqlite3.connect(tmp_path / "snap.sqlite3")
    assert snap.execute("SELECT count(*), max(n) FROM t").fetchone() == (100, 99)   # committed rows only
    assert snap.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    snap.close()

    delta, chroma, extra = (tmp_path / n for n in ("delta", "chroma", "spark"))
    for d in (delta, chroma, extra):
        d.mkdir()
    cmds = plan("r2:bucket/gla/", "/stage", str(delta), str(chroma), {"spark": str(extra)}, skip_chroma=False)
    targets = [(c[3], c[4:]) for c in cmds]
    assert targets == [
        ("r2:bucket/gla/sqlite", []),
        ("r2:bucket/gla/delta-lake", NO_LOG), ("r2:bucket/gla/delta-lake", LOG_ONLY),
        ("r2:bucket/gla/chroma", []),
        ("r2:bucket/gla/spark", NO_LOG), ("r2:bucket/gla/spark", LOG_ONLY),
    ]
    skipped = plan("d:/b", "/stage", str(delta), str(tmp_path / "missing"), {}, skip_chroma=True)
    assert [c[3] for c in skipped] == ["d:/b/sqlite", "d:/b/delta-lake", "d:/b/delta-lake"]


# --- analyzers (fake LLM, no network) ------------------------------------------------------

_TRIAGE_INCIDENT = {
    "id": "inc-1", "kind": "error_spike", "message": "Error spike: 30 errors", "api_token": "SECRET-TOKEN",
    "details": {"count": 30, "sources": ["payments-api"], "samples": ["pool exhausted"], "origin": "spark"},
    "deployments": [{"service": "payments-api", "version": "v2.4.0", "commit_sha": "abc", "url": "http://internal.invalid"}],
}


def _fake_gemini(monkeypatch, error=None):
    """Replaces the Gemini client; returns the list of message lists the analyzer sent."""
    import langchain_google_genai

    calls = []

    class FakeLLM:
        def __init__(self, **kwargs):
            pass

        def with_structured_output(self, schema):
            class Structured:
                async def ainvoke(self, messages):
                    calls.append(messages)
                    if error is not None:
                        raise error
                    return schema(severity="high", hypotheses=["pool too small"], mitigations=["roll back"],
                                  next_steps=["Follow Payments pool"], impact="checkout fails")
            return Structured()

    monkeypatch.setattr(langchain_google_genai, "ChatGoogleGenerativeAI", FakeLLM)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    return calls


def test_gemini_triage_builds_prompt_from_whitelisted_fields_and_references(monkeypatch):
    import asyncio
    from core.analyzers.gemini_incident_triage import SYSTEM, GeminiIncidentTriageAnalyzer

    calls = _fake_gemini(monkeypatch)

    class FakeKnowledge:
        def __init__(self):
            self.searches = []

        def search(self, query, limit=3):
            self.searches.append((query, limit))
            return [{"id": "runbook-1", "kind": "runbook", "title": "Payments pool", "url": None,
                     "distance": 0.4, "content": "x" * 3000}]

    kb = FakeKnowledge()
    out = asyncio.run(GeminiIncidentTriageAnalyzer(knowledge=kb).analyze({"incident": _TRIAGE_INCIDENT}))

    system, human = (m[1] for m in calls[0])
    assert system == SYSTEM
    assert "v2.4.0" in human and "pool exhausted" in human and '<reference kind="runbook" title="Payments pool">' in human
    assert "SECRET-TOKEN" not in human and "internal.invalid" not in human and "origin" not in human
    assert "x" * 1500 in human and "x" * 1501 not in human          # reference text is capped
    assert kb.searches[0][1] == 3 and "payments-api" in kb.searches[0][0]
    assert out["status"] == "ok" and out["severity"] == "high"
    assert out["references"] == [{"id": "runbook-1", "kind": "runbook", "title": "Payments pool",
                                  "url": None, "distance": 0.4}]


def test_gemini_triage_reports_llm_failure_and_works_without_knowledge(monkeypatch):
    import asyncio
    from core.analyzers.gemini_incident_triage import GeminiIncidentTriageAnalyzer

    calls = _fake_gemini(monkeypatch, error=RuntimeError("quota exceeded"))
    out = asyncio.run(GeminiIncidentTriageAnalyzer().analyze({"incident": _TRIAGE_INCIDENT}))
    assert out["status"] == "failed" and out["error"] == "RuntimeError" and "quota" in out["detail"]
    assert "<reference" not in calls[0][1][1]


def test_missing_gemini_key_blocks_triage_but_not_other_analyzers(monkeypatch, tmp_path):
    import asyncio
    import pytest
    from api.main import orchestrator
    from core.analyzer_runner import AnalyzerRunner
    from core.analyzers.gemini_incident_triage import GeminiIncidentTriageAnalyzer
    from core.analyzers.simple_incident_summary import SimpleIncidentSummaryAnalyzer
    from core.event_bus import EventBus
    from core.incident_store import IncidentStore
    from core.plugin_registry import PluginRegistry, PluginSpec
    from core.triage import TriageService

    monkeypatch.setenv("GEMINI_API_KEY", "")
    with pytest.raises(RuntimeError, match="GEMINI_API_KEY"):
        GeminiIncidentTriageAnalyzer()

    # POST /analyze answers 503 when no engine could be built.
    monkeypatch.setenv("ENABLE_AUTH", "false")
    monkeypatch.setattr(orchestrator, "engine", None)
    assert TestClient(app).post("/analyze", json={"query": "why"}).status_code == 503

    # The runner skips the analyzer that cannot start and still attaches the others.
    registry = PluginRegistry()
    registry.register(PluginSpec(name="gemini_triage", kind="analyzer", factory=GeminiIncidentTriageAnalyzer))
    registry.register(PluginSpec(name="simple_summary", kind="analyzer", factory=SimpleIncidentSummaryAnalyzer))
    store = IncidentStore(str(tmp_path / "inc.sqlite3"))
    triage = TriageService(store)
    inc, _ = triage.raise_incident("error_spike", "spike", {"count": 3, "sources": ["a"], "source_counts": {"a": 3}})

    async def scenario():
        bus = EventBus()
        runner = AnalyzerRunner(bus, registry, triage, ["gemini_triage", "simple_summary"])
        await runner.start()
        await bus.publish({"incident_id": inc.id, "incident": inc.to_dict()})
        await bus.publish({"incident_id": None, "incident": None})        # malformed events are ignored
        await asyncio.sleep(0.5)
        await runner.stop()

    asyncio.run(scenario())
    [analysis] = store.analyses(inc.id)
    assert analysis["analyzer"] == "simple_summary" and "spike" in analysis["summary"]


# --- Kafka consumer and connector (fake aiokafka objects) ----------------------------------

def _kafka_run(monkeypatch, polls, fail_first_batches=0):
    """Drives LogConsumer.run with scripted polls. Returns (events, batches)."""
    import asyncio
    from collections import namedtuple
    from aiokafka import ConsumerStoppedError
    from ingestion.kafka_consumer import LogConsumer

    TP = namedtuple("TP", "topic partition")
    Msg = namedtuple("Msg", "value offset")
    events, batches, script = [], [], list(polls)

    class FakeConsumer:
        async def getmany(self, timeout_ms, max_records):
            if not script:
                raise ConsumerStoppedError()
            poll = script.pop(0)
            return {TP("logs-raw", 0): [Msg(v, o) for o, v in poll]} if poll else {}

        async def commit(self):
            events.append("commit")

        def seek(self, tp, offset):
            events.append(f"seek:{offset}")

        async def stop(self):
            events.append("stop")

    failures = [fail_first_batches]

    async def on_batch(logs):
        batches.append(logs)
        events.append(f"batch:{len(logs)}")
        if failures[0] > 0:
            failures[0] -= 1
            raise RuntimeError("store down")

    async def no_sleep(_delay):
        events.append("sleep")

    monkeypatch.setattr("ingestion.kafka_consumer.asyncio.sleep", no_sleep)
    consumer = LogConsumer(on_batch, max_batch=10)
    consumer.consumer, consumer._running = FakeConsumer(), True
    asyncio.run(consumer.run())
    return events, batches


def test_kafka_consumer_decodes_batch_and_commits_after_store(monkeypatch):
    good = [b'{"message": "a"}', b'{"message": "b"}']
    events, batches = _kafka_run(monkeypatch, [[(0, good[0]), (1, b"not json"), (2, b"[1]"), (3, good[1])]])
    assert batches == [[{"message": "a"}, {"message": "b"}]]       # junk and non-objects are dropped
    assert events == ["batch:2", "commit", "stop"]                 # offsets move only after the store call


def test_kafka_consumer_skips_empty_polls_and_commits_junk_only_batches(monkeypatch):
    events, batches = _kafka_run(monkeypatch, [[], [(0, b"junk")]])
    assert batches == [] and events == ["commit", "stop"]


def test_kafka_consumer_rewinds_and_retries_when_the_store_fails(monkeypatch):
    msg = [(7, b'{"message": "a"}'), (8, b'{"message": "b"}')]
    events, batches = _kafka_run(monkeypatch, [msg, msg], fail_first_batches=1)
    assert events == ["batch:2", "seek:7", "sleep", "batch:2", "commit", "stop"]   # no commit past a failed batch
    assert batches[0] == batches[1]


def test_kafka_connector_retries_with_backoff_until_the_broker_is_up(monkeypatch):
    import asyncio
    import aiokafka
    from core.connectors.kafka_connector import KafkaConnector
    from ingestion.kafka_consumer import LogConsumer

    # Unreachable broker: start() reports False and leaves no half-open consumer behind.
    class Unreachable:
        def __init__(self, *a, **k):
            pass

        async def start(self):
            raise OSError("no broker")

    monkeypatch.setattr(aiokafka, "AIOKafkaConsumer", Unreachable)
    consumer = LogConsumer(lambda logs: None)
    assert asyncio.run(consumer.start()) is False and consumer.consumer is None

    delays, state = [], {"starts": [False, False, True], "ran": 0}
    connector = KafkaConnector(lambda logs: None)

    class FakeConsumer:
        async def start(self):
            return state["starts"].pop(0)

        async def run(self):
            state["ran"] += 1
            connector._stopping = True

    async def fake_sleep(delay):
        delays.append(delay)

    monkeypatch.setattr("core.connectors.kafka_connector.asyncio.sleep", fake_sleep)
    connector._consumer = FakeConsumer()
    asyncio.run(connector._connect_and_run("kafka:29092"))
    assert delays == [2.0, 4.0] and state["ran"] == 1               # doubles per failure, stops once consuming
