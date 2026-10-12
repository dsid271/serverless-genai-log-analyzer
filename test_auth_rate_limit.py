"""Tests for API-key auth / RBAC (api.auth) and rate limiting (api.rate_limit)."""

import bcrypt
import pytest
import yaml
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.requests import Request as StarletteRequest

from api import auth
from api.main import app as real_app
from api.rate_limit import _get_identity

# Distinct first 10 characters: the limiter keys on key[:10].
KEYS = {
    "admin": "admin-test-key",
    "analyst": "analyst-test-key",
    "viewer": "viewer-test-key",
}


def _hash(raw: str) -> str:
    return bcrypt.hashpw(raw.encode(), bcrypt.gensalt(rounds=4)).decode()


def _configure_keys(tmp_path, monkeypatch, entries):
    path = tmp_path / "keys.yaml"
    path.write_text(yaml.safe_dump({"keys": entries}))
    monkeypatch.setenv("API_KEYS_FILE", str(path))
    monkeypatch.setenv("ENABLE_AUTH", "true")
    auth._load_keys.cache_clear()


@pytest.fixture
def auth_on(tmp_path, monkeypatch):
    entries = [
        {"name": f"{role}-test", "key_hash": _hash(raw), "role": role}
        for role, raw in KEYS.items()
    ]
    _configure_keys(tmp_path, monkeypatch, entries)
    yield
    auth._load_keys.cache_clear()


def _header(role):
    return {"X-API-Key": KEYS[role]}


# ---------------------------------------------------------------------------
# Auth: minimal app exercising require_role directly
# ---------------------------------------------------------------------------

def _role_app() -> FastAPI:
    app = FastAPI()

    @app.get("/admin", dependencies=[Depends(auth.require_role("admin"))])
    async def admin_only():
        return {"ok": True}

    @app.get("/write", dependencies=[Depends(auth.require_role("admin", "analyst"))])
    async def writers():
        return {"ok": True}

    @app.get("/read", dependencies=[Depends(auth.require_role("admin", "analyst", "viewer"))])
    async def readers():
        return {"ok": True}

    return app


def test_auth_disabled_treats_everyone_as_admin(monkeypatch):
    monkeypatch.setenv("ENABLE_AUTH", "false")
    client = TestClient(_role_app())
    assert client.get("/admin").status_code == 200


def test_missing_key_is_rejected(auth_on):
    response = TestClient(_role_app()).get("/read")
    assert response.status_code == 403
    assert "Missing API key" in response.json()["detail"]


def test_invalid_key_is_rejected(auth_on):
    response = TestClient(_role_app()).get("/read", headers={"X-API-Key": "wrong-key"})
    assert response.status_code == 403
    assert "Invalid API key" in response.json()["detail"]


def test_overlong_key_is_rejected_not_500(auth_on):
    # bcrypt rejects secrets over 72 bytes; that must surface as 403, never a server error.
    response = TestClient(_role_app()).get("/read", headers={"X-API-Key": "x" * 100})
    assert response.status_code == 403


@pytest.mark.parametrize(
    "role,path,expected",
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
def test_role_matrix(auth_on, role, path, expected):
    response = TestClient(_role_app()).get(path, headers=_header(role))
    assert response.status_code == expected, response.text


def test_forbidden_role_error_names_the_role(auth_on):
    response = TestClient(_role_app()).get("/admin", headers=_header("viewer"))
    assert response.status_code == 403
    assert "viewer" in response.json()["detail"]


def test_malformed_hash_entry_does_not_break_other_keys(tmp_path, monkeypatch):
    entries = [
        {"name": "broken", "key_hash": "not-a-bcrypt-hash", "role": "admin"},
        {"name": "good", "key_hash": _hash("good-test-key"), "role": "viewer"},
    ]
    _configure_keys(tmp_path, monkeypatch, entries)
    try:
        client = TestClient(_role_app())
        assert client.get("/read", headers={"X-API-Key": "good-test-key"}).status_code == 200
        assert client.get("/read", headers={"X-API-Key": "nope"}).status_code == 403
    finally:
        auth._load_keys.cache_clear()


def test_missing_keys_file_denies_everything(tmp_path, monkeypatch):
    monkeypatch.setenv("ENABLE_AUTH", "true")
    monkeypatch.setenv("API_KEYS_FILE", str(tmp_path / "does-not-exist.yaml"))
    auth._load_keys.cache_clear()
    try:
        response = TestClient(_role_app()).get("/read", headers={"X-API-Key": "anything"})
        assert response.status_code == 403
    finally:
        auth._load_keys.cache_clear()


# ---------------------------------------------------------------------------
# Auth: role enforcement on the real application's routes
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
    "role,route",
    [
        ("viewer", "ingest"),
        ("viewer", "search"),
        ("viewer", "analyze"),
        ("viewer", "audit"),
        ("analyst", "audit"),
    ],
)
def test_real_app_forbids_insufficient_role(auth_on, role, route):
    response = _call(TestClient(real_app), route, _header(role))
    assert response.status_code == 403, response.text


@pytest.mark.parametrize(
    "role,route",
    [
        ("viewer", "incidents"),
        ("viewer", "summary"),
        ("viewer", "plugins"),
        ("analyst", "search"),
        ("admin", "audit"),
    ],
)
def test_real_app_allows_sufficient_role(auth_on, role, route):
    response = _call(TestClient(real_app), route, _header(role))
    assert response.status_code == 200, response.text


@pytest.mark.parametrize("route", sorted(REAL_ROUTES))
def test_real_app_requires_key_on_every_protected_route(auth_on, route):
    assert _call(TestClient(real_app), route).status_code == 403


def test_health_route_is_public(auth_on):
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


def test_identity_prefers_authenticated_user():
    request = _request({"X-API-Key": "abcdefghijklmnop"})
    request.state.user = auth.User(name="alice", role="admin")
    assert _get_identity(request) == "user:alice"


def test_identity_falls_back_to_api_key_prefix():
    assert _get_identity(_request({"X-API-Key": "abcdefghijklmnop"})) == "key:abcdefghij"


def test_identity_falls_back_to_client_ip():
    assert _get_identity(_request()) == "203.0.113.7"


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
    assert client.get("/limited", headers=_header("admin")).status_code == 200
    assert client.get("/limited", headers=_header("admin")).status_code == 429
    # A different key has its own bucket.
    assert client.get("/limited", headers=_header("viewer")).status_code == 200


def test_real_app_wires_limiter_and_429_handler():
    from api.main import limiter

    assert real_app.state.limiter is limiter
    assert RateLimitExceeded in real_app.exception_handlers
