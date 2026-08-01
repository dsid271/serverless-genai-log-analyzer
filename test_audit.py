import os
import sys
import tempfile
import types
import pandas as pd

from api.audit import AuditLogger


def test_audit_logger_pii_contains_persisted(monkeypatch, tmp_path):
    captured = {}

    fake_deltalake = types.SimpleNamespace()

    def fake_write_deltalake(path, df, mode, schema_mode):
        captured["path"] = path
        captured["event"] = df.to_dict(orient="records")[0]

    class FakeDeltaTable:
        def __init__(self, path):
            self.path = path

        def to_pandas(self):
            return pd.DataFrame([])

    fake_deltalake.write_deltalake = fake_write_deltalake
    fake_deltalake.DeltaTable = FakeDeltaTable
    monkeypatch.setitem(sys.modules, "deltalake", fake_deltalake)
    monkeypatch.setattr("api.audit.write_deltalake", fake_write_deltalake)

    logger = AuditLogger(str(tmp_path / "audit_trail"))
    logger.log_event(
        request_id="req-123",
        user="test-user",
        action="POST /ingest",
        query_params="",
        results_count=1,
        pii_accessed=False,
        contains_pii=True,
        duration_ms=12.3,
        status_code=200,
        error="",
    )

    assert captured["path"] == os.path.join(str(tmp_path), "audit_trail")
    assert captured["event"]["contains_pii"] is True
    assert captured["event"]["pii_accessed"] is False


def test_audit_logger_query_adds_contains_pii_for_legacy(monkeypatch, tmp_path):
    events = [
        {
            "timestamp": 1.0,
            "request_id": "req-legacy",
            "user": "legacy-user",
            "action": "POST /ingest",
            "query_params": "",
            "results_count": 1,
            "pii_accessed": True,
            "duration_ms": 55.5,
            "status_code": 200,
            "error": "",
        }
    ]

    fake_df = pd.DataFrame(events)
    fake_deltalake = types.SimpleNamespace()

    def fake_write_deltalake(path, df, mode, schema_mode):
        pass

    class FakeDeltaTable:
        def __init__(self, path):
            self.path = path

        def to_pandas(self):
            return fake_df

    fake_deltalake.write_deltalake = fake_write_deltalake
    fake_deltalake.DeltaTable = FakeDeltaTable
    monkeypatch.setitem(sys.modules, "deltalake", fake_deltalake)

    logger = AuditLogger(str(tmp_path / "audit_trail"))
    # Create the directory path so query will not short-circuit on missing table path.
    os.makedirs(str(tmp_path / "audit_trail"), exist_ok=True)
    result = logger.query()

    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["contains_pii"] is True
    assert result[0]["pii_accessed"] is True
