import os

import pandas as pd
from deltalake import DeltaTable, write_deltalake

import api.audit as audit_module
from api.audit import AuditLogger


def test_audit_logger_persists_detail(tmp_path):
    table = str(tmp_path / "audit_trail")
    AuditLogger(table).log_event(request_id="r1", user="u", action="POST /search", detail="query=disk full limit=5")
    assert DeltaTable(table).to_pandas().iloc[0]["detail"] == "query=disk full limit=5"


def test_failed_write_is_spooled_then_replayed(tmp_path, monkeypatch):
    table = str(tmp_path / "audit_trail")
    logger = AuditLogger(table)
    real_write = audit_module.write_deltalake

    def broken(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(audit_module, "write_deltalake", broken)
    logger.log_event(request_id="req-1", user="u", action="GET /a")
    assert not os.path.exists(table)
    assert os.path.exists(logger.spool_path)

    monkeypatch.setattr(audit_module, "write_deltalake", real_write)
    logger.log_event(request_id="req-2", user="u", action="GET /b")
    assert sorted(DeltaTable(table).to_pandas()["request_id"]) == ["req-1", "req-2"]
    assert not os.path.exists(logger.spool_path)


def test_audit_logger_pii_contains_persisted(tmp_path):
    table = str(tmp_path / "audit_trail")
    logger = AuditLogger(table)
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

    rows = DeltaTable(table).to_pandas().to_dict(orient="records")
    assert len(rows) == 1
    assert bool(rows[0]["contains_pii"]) is True
    assert bool(rows[0]["pii_accessed"]) is False


def test_audit_logger_query_adds_contains_pii_for_legacy(tmp_path):
    # A table written before the contains_pii column existed.
    table = str(tmp_path / "audit_trail")
    legacy = [
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

    write_deltalake(table, pd.DataFrame(legacy), mode="append")

    result = AuditLogger(table).query()

    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["contains_pii"] is True
    assert result[0]["pii_accessed"] is True
