"""
API Key Authentication & scope-based authorization for the GenAI Log Analyzer.

- Keys are issued per profile and stored in SQLite (see api/key_store.py).
  Issue them with `scripts/manage_keys.py` or `POST /admin/keys`.
- Auth is opt-in: set ENABLE_AUTH=true to enforce. When disabled, all requests
  are treated as an anonymous user with every scope.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import FrozenSet, Optional

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader

from api.key_store import SCOPES, get_key_store

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class User:
    name: str
    profile: str
    scopes: FrozenSet[str]
    key_id: Optional[str] = None


_ANONYMOUS_ADMIN = User(name="anonymous", profile="admin", scopes=SCOPES)

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _verify_key(raw_key: str) -> Optional[User]:
    record = get_key_store().verify(raw_key)
    if record is None:
        return None
    return User(name=record.name, profile=record.profile, scopes=record.scopes, key_id=record.key_id)


def _auth_enabled() -> bool:
    val = os.getenv("ENABLE_AUTH", "")
    return val.strip().lower() in {"1", "true", "yes", "y", "on"}

# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

async def get_current_user(
    request: Request,
    api_key: Optional[str] = Security(_api_key_header),
) -> User:
    """
    Resolve the current user from the X-API-Key header.
    When auth is disabled, returns an anonymous user with every scope.
    """
    if not _auth_enabled():
        user = _ANONYMOUS_ADMIN
    elif not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Provide X-API-Key header.",
        )
    else:
        verified = _verify_key(api_key)
        if verified is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid, expired or revoked API key.",
            )
        user = verified

    request.state.user = user
    request.state.user_identity = f"{user.name}:{user.key_id}" if user.key_id else user.name
    return user


def require_scope(*required: str):
    """
    Dependency factory: ensures the authenticated key holds every listed scope.

    Usage:
        @app.get("/audit-trail", dependencies=[Depends(require_scope("audit:read"))])
    """
    unknown = set(required) - SCOPES
    if unknown:
        raise ValueError(f"Unknown scopes: {sorted(unknown)}")

    async def _check(user: User = Depends(get_current_user)) -> User:
        missing = set(required) - user.scopes
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Key lacks required scope(s): {sorted(missing)}",
            )
        return user

    return _check
