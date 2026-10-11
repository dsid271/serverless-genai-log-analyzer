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
                    "request_id": "req-test-0001"
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

        search_payload = {"query": "endpoint coverage", "limit": 1}
        search_response = client.post("/search", json=search_payload)
        assert search_response.status_code == 200, search_response.text
        search_json = search_response.json()
        assert "results" in search_json
        assert isinstance(search_json["results"], list)

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
