"""Tests for API-key auth / scopes (api.auth, api.key_store) and rate limiting (api.rate_limit)."""

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.requests import Request as StarletteRequest

from api import auth
from api.key_store import get_key_store
from api.main import app as real_app
from api.rate_limit import _get_identity

PROFILES = ("admin", "analyst", "viewer")


@pytest.fixture
def keys(tmp_path, monkeypatch):
    monkeypatch.setenv("API_KEYS_DB", str(tmp_path / "keys.sqlite3"))
    monkeypatch.setenv("ENABLE_AUTH", "true")
    store = get_key_store()
    return {profile: store.issue(f"{profile}-test", profile)[0] for profile in PROFILES}


def _header(keys, profile):
    return {"X-API-Key": keys[profile]}


# ---------------------------------------------------------------------------
# Auth: minimal app exercising require_scope directly
# ---------------------------------------------------------------------------

def _scope_app() -> FastAPI:
    app = FastAPI()

    @app.get("/admin", dependencies=[Depends(auth.require_scope("keys:admin"))])
    async def admin_only():
        return {"ok": True}

    @app.get("/write", dependencies=[Depends(auth.require_scope("logs:ingest"))])
    async def writers():
        return {"ok": True}

    @app.get("/read", dependencies=[Depends(auth.require_scope("incidents:read"))])
    async def readers():
        return {"ok": True}

    return app


def test_unknown_scope_is_rejected_at_definition():
    with pytest.raises(ValueError):
        auth.require_scope("no:such-scope")


def test_auth_disabled_treats_everyone_as_admin(monkeypatch):
    monkeypatch.setenv("ENABLE_AUTH", "false")
    client = TestClient(_scope_app())
    assert client.get("/admin").status_code == 200


def test_missing_key_is_rejected(keys):
    response = TestClient(_scope_app()).get("/read")
    assert response.status_code == 401
    assert "Missing API key" in response.json()["detail"]


def test_invalid_key_is_rejected(keys):
    response = TestClient(_scope_app()).get("/read", headers={"X-API-Key": "wrong-key"})
    assert response.status_code == 401
    assert "Invalid" in response.json()["detail"]


def test_wrong_secret_for_known_key_id_is_rejected(keys):
    key_id = keys["admin"].split("_", 2)[1]
    response = TestClient(_scope_app()).get("/read", headers={"X-API-Key": f"gla_{key_id}_not-the-secret"})
    assert response.status_code == 401


def test_overlong_key_is_rejected_not_500(keys):
    response = TestClient(_scope_app()).get("/read", headers={"X-API-Key": "x" * 100})
    assert response.status_code == 401


@pytest.mark.parametrize(
    "profile,path,expected",
    [
        ("admin", "/admin", 200),
        ("admin", "/write", 200),
        ("admin", "/read", 200),
        ("analyst", "/admin", 403),
        ("analyst", "/write", 200),
        ("analyst", "/read", 200),
        ("viewer", "/admin", 403),
        ("viewer", "/write", 403),
        ("viewer", "/read", 200),
    ],
)
def test_profile_matrix(keys, profile, path, expected):
    response = TestClient(_scope_app()).get(path, headers=_header(keys, profile))
    assert response.status_code == expected, response.text


def test_forbidden_error_names_the_missing_scope(keys):
    response = TestClient(_scope_app()).get("/admin", headers=_header(keys, "viewer"))
    assert response.status_code == 403
    assert "keys:admin" in response.json()["detail"]


def test_revoked_key_is_rejected(keys):
    client = TestClient(_scope_app())
    assert client.get("/read", headers=_header(keys, "viewer")).status_code == 200
    get_key_store().revoke(keys["viewer"].split("_", 2)[1])
    assert client.get("/read", headers=_header(keys, "viewer")).status_code == 401


def test_expired_key_is_rejected(keys, monkeypatch):
    import time

    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 181 * 86400)
    response = TestClient(_scope_app()).get("/read", headers=_header(keys, "viewer"))
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Auth: scope enforcement on the real application's routes
# ---------------------------------------------------------------------------

REAL_ROUTES = {
    "ingest": ("POST", "/ingest", {"logs": []}),
    "search": ("POST", "/search", {"query": "x"}),
    "analyze": ("POST", "/analyze", {"query": "x"}),
    "audit": ("GET", "/audit-trail", None),
    "incidents": ("GET", "/incidents", None),
    "summary": ("GET", "/summary", None),
    "plugins": ("GET", "/plugins", None),
}


def _call(client, route, headers=None):
    method, path, body = REAL_ROUTES[route]
    return client.request(method, path, json=body, headers=headers)


@pytest.mark.parametrize(
    "profile,route",
    [
        ("viewer", "ingest"),
        ("viewer", "search"),
        ("viewer", "analyze"),
        ("viewer", "audit"),
        ("analyst", "audit"),
    ],
)
def test_real_app_forbids_insufficient_profile(keys, profile, route):
    response = _call(TestClient(real_app), route, _header(keys, profile))
    assert response.status_code == 403, response.text


@pytest.mark.parametrize(
    "profile,route",
    [
        ("viewer", "incidents"),
        ("viewer", "summary"),
        ("viewer", "plugins"),
        ("analyst", "search"),
        ("admin", "audit"),
    ],
)
def test_real_app_allows_sufficient_profile(keys, profile, route):
    response = _call(TestClient(real_app), route, _header(keys, profile))
    assert response.status_code == 200, response.text


@pytest.mark.parametrize("route", sorted(REAL_ROUTES))
def test_real_app_requires_key_on_every_protected_route(keys, route):
    assert _call(TestClient(real_app), route).status_code == 401


def test_health_route_is_public(keys):
    assert TestClient(real_app).get("/").status_code == 200


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def _request(headers=None, client=("203.0.113.7", 5000)):
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "client": client,
    }
    return StarletteRequest(scope)


def test_identity_prefers_authenticated_key_id():
    request = _request({"X-API-Key": "gla_other_secret"})
    request.state.user = auth.User(name="alice", profile="admin", scopes=frozenset(), key_id="abc123")
    assert _get_identity(request) == "key:abc123"


def test_identity_uses_user_name_without_key_id():
    request = _request()
    request.state.user = auth.User(name="anonymous", profile="admin", scopes=frozenset())
    assert _get_identity(request) == "user:anonymous"


def test_identity_falls_back_to_key_id_from_header():
    assert _get_identity(_request({"X-API-Key": "gla_abc123_topsecret"})) == "key:abc123"


def test_identity_never_contains_the_secret():
    assert "topsecret" not in _get_identity(_request({"X-API-Key": "gla_abc123_topsecret"}))


def test_identity_falls_back_to_client_ip():
    assert _get_identity(_request()) == "203.0.113.7"
    assert _get_identity(_request({"X-API-Key": "not-a-gla-key"})) == "203.0.113.7"


def _limited_app(limit: str) -> FastAPI:
    # Fresh Limiter per app so buckets never leak between tests.
    limiter = Limiter(key_func=_get_identity)
    app = FastAPI()
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    @app.get("/limited")
    @limiter.limit(limit)
    async def limited(request: Request):
        return {"ok": True}

    return app


def test_limit_is_enforced_with_429():
    client = TestClient(_limited_app("2/minute"))
    assert client.get("/limited").status_code == 200
    assert client.get("/limited").status_code == 200
    blocked = client.get("/limited")
    assert blocked.status_code == 429
    assert "Rate limit exceeded" in blocked.text


def test_limits_are_tracked_per_api_key():
    client = TestClient(_limited_app("1/minute"))
    first, second = {"X-API-Key": "gla_aaaa_one"}, {"X-API-Key": "gla_bbbb_two"}
    assert client.get("/limited", headers=first).status_code == 200
    assert client.get("/limited", headers=first).status_code == 429
    # A different key has its own bucket.
    assert client.get("/limited", headers=second).status_code == 200


def test_real_app_wires_limiter_and_429_handler():
    from api.main import limiter

    assert real_app.state.limiter is limiter
    assert RateLimitExceeded in real_app.exception_handlers
