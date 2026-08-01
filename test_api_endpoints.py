import os
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
        assert "events" in audit_response.json()
