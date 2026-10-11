"""
Rate limiting configuration using SlowAPI.
"""

from __future__ import annotations

import os

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from api.auth import User
from api.key_store import parse_key

def _get_identity(request: Request) -> str:
    """
    Identity function for rate limiting.
    Uses the authenticated key id if available, otherwise the client IP address.
    """
    # get_current_user places the User on request.state
    user = getattr(request.state, "user", None)
    if isinstance(user, User):
        return f"key:{user.key_id}" if user.key_id else f"user:{user.name}"

    parsed = parse_key(request.headers.get("X-API-Key", ""))
    if parsed:
        # key_id only; the secret part never becomes a limiter key
        return f"key:{parsed[0]}"

    return get_remote_address(request)


# Global Limiter instance
limiter = Limiter(key_func=_get_identity)

# Configuration from env
rate_limit_default = os.getenv("RATE_LIMIT_DEFAULT", "100/minute")
rate_limit_ingest = os.getenv("RATE_LIMIT_INGEST", "50/minute")
rate_limit_analyze = os.getenv("RATE_LIMIT_ANALYZE", "10/minute")
