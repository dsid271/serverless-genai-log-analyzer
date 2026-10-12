import pytest
from fastapi.testclient import TestClient

from api.main import app
from processing.format_profiles import FormatNormalizer, get_normalizer


@pytest.fixture(scope="module")
def norm() -> FormatNormalizer:
    return get_normalizer()


def one(norm, log, profile):
    return norm.normalize_batch([log], profile)[0]


def test_generic_passthrough_is_unchanged(norm):
    log = {"timestamp": "2026-10-11T10:00:01Z", "severity": "ERROR", "source": "svc", "message": "boom", "x": 1}
    assert one(norm, log, "generic") == log


def test_generic_aliases_and_level_names(norm):
    out = one(norm, {"ts": 1700000000, "level": "fatal", "service": "api", "msg": "down"}, "generic")
    assert out["severity"] == "CRITICAL"
    assert out["source"] == "api"
    assert out["message"] == "down"
    assert out["timestamp"] == "2023-11-14T22:13:20Z"
    assert not {"ts", "level", "service", "msg"} & out.keys()


def test_epoch_units_normalise_to_same_instant(norm):
    expected = "2023-11-14T22:13:20Z"
    for value in (1700000000, 1700000000000, 1700000000000000, 1700000000000000000, "1700000000"):
        assert one(norm, {"time": value}, "generic")["timestamp"] == expected


def test_siem_hec_envelope_with_object_and_string_event(norm):
    out = one(norm, {"time": 1700000000.5, "sourcetype": "orders", "event": {"level": "warn", "message": "slow"}}, "siem_hec")
    assert (out["severity"], out["source"], out["message"]) == ("WARNING", "orders", "slow")
    assert out["timestamp"] == "2023-11-14T22:13:20.500000Z"
    out = one(norm, {"time": 1700000000, "source": "edge", "event": "plain text line"}, "siem_hec")
    assert out["message"] == "plain text line" and "event" not in out


def test_acme_insight_custom_timestamp_format(norm):
    out = one(norm, {"_time": "2026-10-11 10:00:01,250", "log_level": "SEVERE", "svc": "billing", "msg": "x"}, "acme_insight")
    assert out["timestamp"] == "2026-10-11T10:00:01.250000Z"
    assert out["severity"] == "ERROR" and out["source"] == "billing"


def test_acme_ai_platform_otel_nested_fields_and_numeric_severity(norm):
    log = {
        "timeUnixNano": "1700000000000000000",
        "severityNumber": 17,
        "resource": {"attributes": {"service": {"name": "llm-gateway"}, "region": "r1"}},
        "body": {"prompt_tokens": 12},
    }
    out = one(norm, log, "acme_ai_platform")
    assert out["severity"] == "ERROR"
    assert out["source"] == "llm-gateway"
    assert out["message"] == '{"prompt_tokens": 12}'
    assert out["resource"]["attributes"] == {"region": "r1"}
    # The caller's record must not be mutated.
    assert log["resource"]["attributes"]["service"] == {"name": "llm-gateway"}


def test_default_severity_and_unparseable_timestamp(norm):
    out = one(norm, {"timestamp": "not a date", "service.name": "s", "body": "m"}, "acme_ai_platform")
    assert out["severity"] == "INFO"
    assert out["timestamp"] == "not a date"
    assert out["source"] == "s"


def test_unknown_profile_raises(norm):
    with pytest.raises(KeyError):
        norm.normalize_batch([{}], "nope")


def test_ingest_route_applies_profile_and_rejects_unknown(monkeypatch):
    monkeypatch.setenv("ENABLE_AUTH", "false")
    monkeypatch.setenv("ENABLED_DETECTORS", "")
    monkeypatch.setenv("ENABLED_ANALYZERS", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")
    with TestClient(app) as client:
        ok = client.post("/ingest", json={
            "format": "acme_insight",
            "logs": [{"_time": 1700000000, "log_level": "ERR", "svc": "billing", "msg": "pool exhausted"}],
        })
        assert ok.status_code == 200, ok.text
        assert ok.json()["count"] == 1

        bad = client.post("/ingest", json={"format": "does_not_exist", "logs": [{"message": "x"}]})
        assert bad.status_code == 400
        assert "acme_insight" in bad.json()["detail"]


def test_spark_record_processor_normalizes_redacts_and_patterns(monkeypatch, tmp_path):
    import json

    monkeypatch.setenv("PII_LEARNED_DB", str(tmp_path / "learned.sqlite3"))
    from spark.transform import COLUMNS, RecordProcessor

    proc = RecordProcessor(format_profile="acme_insight")
    raw = json.dumps({"_time": 1700000000, "log_level": "ERR", "svc": "billing",
                      "msg": "card 4111 1111 1111 1111 declined after 350ms"}).encode()
    row = proc.process(raw, kafka_ts="ts")
    assert set(row) == set(COLUMNS)
    assert row["source"] == "billing" and row["severity"] == "ERROR" and row["is_error"] is True
    assert row["timestamp"].startswith("2023-11-14")
    assert "4111 1111 1111 1111" not in row["message"] and "4111" not in row["record"]
    assert row["contains_pii"] is True and row["redaction_mode"] == "rules-only"
    assert row["kafka_ts"] == "ts"

    again = proc.process(json.dumps({"_time": 1700000001, "log_level": "ERR", "svc": "billing",
                                     "msg": "card 4111 1111 1111 1111 declined after 12ms"}))
    assert again["pattern_id"] == row["pattern_id"] and "<n>ms" in again["pattern"]

    assert proc.process(b"not json") is None
    assert proc.process(b"[1, 2]") is None
    with pytest.raises(ValueError):
        RecordProcessor(format_profile="does_not_exist")
