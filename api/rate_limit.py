"""
Rate limiting configuration using SlowAPI.
"""

from __future__ import annotations

import os

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from api.auth import User

def _get_identity(request: Request) -> str:
    """
    Identity function for rate limiting.
    Uses the X-API-Key if available, otherwise falls back to the client IP address.
    """
    # Assuming auth middleware places the User object or API key in request state if auth is enabled
    if hasattr(request.state, "user") and isinstance(request.state.user, User):
        return f"user:{request.state.user.name}"
    
    api_key = request.headers.get("X-API-Key")
    if api_key:
        # In a real app, hash this before using it as a key
        return f"key:{api_key[:10]}"
        
    return get_remote_address(request)


# Global Limiter instance
limiter = Limiter(key_func=_get_identity)

# Configuration from env
rate_limit_default = os.getenv("RATE_LIMIT_DEFAULT", "100/minute")
rate_limit_ingest = os.getenv("RATE_LIMIT_INGEST", "50/minute")
rate_limit_analyze = os.getenv("RATE_LIMIT_ANALYZE", "10/minute")
