"""
API Key Authentication & RBAC for the GenAI Log Analyzer.

- Keys are stored as bcrypt hashes in api_keys.yaml (Docker-volume-mountable).
- Auth is opt-in: set ENABLE_AUTH=true to enforce. When disabled, all requests
  are treated as admin.
- Roles: admin, analyst, viewer.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Dict, List, Optional

import yaml
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class User:
    name: str
    role: str


_ANONYMOUS_ADMIN = User(name="anonymous", role="admin")

# ---------------------------------------------------------------------------
# Key store — loaded once, cached
# ---------------------------------------------------------------------------

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


@lru_cache(maxsize=1)
def _load_keys() -> List[Dict[str, Any]]:
    config_path = os.getenv(
        "API_KEYS_FILE",
        os.path.join(os.path.dirname(__file__), "api_keys.yaml"),
    )
    try:
        with open(config_path, "r") as f:
            data = yaml.safe_load(f)
        return data.get("keys", [])
    except Exception:
        return []


def _verify_key(raw_key: str) -> Optional[User]:
    """Verify a raw API key against stored bcrypt hashes."""
    try:
        from passlib.hash import bcrypt
    except ImportError:
        # passlib not installed — treat all keys as invalid
        return None

    for entry in _load_keys():
        stored_hash = entry.get("key_hash", "")
        if bcrypt.verify(raw_key, stored_hash):
            return User(name=entry.get("name", "unknown"), role=entry.get("role", "viewer"))
    return None


def _auth_enabled() -> bool:
    val = os.getenv("ENABLE_AUTH", "")
    return val.strip().lower() in {"1", "true", "yes", "y", "on"}

# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

async def get_current_user(
    api_key: Optional[str] = Security(_api_key_header),
) -> User:
    """
    Resolve the current user from the X-API-Key header.
    When auth is disabled, returns an anonymous admin user.
    """
    if not _auth_enabled():
        return _ANONYMOUS_ADMIN

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing API key. Provide X-API-Key header.",
        )

    user = _verify_key(api_key)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key.",
        )
    return user


def require_role(*allowed_roles: str):
    """
    Dependency factory: ensures the authenticated user has one of the
    allowed roles.

    Usage:
        @app.get("/admin-only", dependencies=[Depends(require_role("admin"))])
    """

    async def _check(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user.role}' is not authorized. Required: {allowed_roles}",
            )
        return user

    return _check
