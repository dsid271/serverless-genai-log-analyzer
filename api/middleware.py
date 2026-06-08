"""
Request lifecycle middleware for structured logging and audit trailing.
"""

from __future__ import annotations

import time
import uuid
from contextvars import ContextVar
from typing import Callable

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from api.audit import audit_logger

# Context var for correlating logs across async tasks
request_id_var: ContextVar[str] = ContextVar("request_id", default="")

class AuditLoggingMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # 1. Setup Request ID
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request_id_var.set(request_id)
        request.state.request_id = request_id

        # 2. Setup Structured Logger
        logger = structlog.get_logger().bind(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
        )

        start_time = time.perf_counter()
        logger.info("request_started")

        error_msg = ""
        results_count = 0
        pii_accessed = False
        
        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers["X-Request-ID"] = request_id
            
            # Extract info from state if handlers populated it
            results_count = getattr(request.state, "results_count", 0)
            pii_accessed = getattr(request.state, "pii_accessed", False)
            user_identity = getattr(request.state, "user_identity", "anonymous")
            
        except Exception as e:
            status_code = 500
            error_msg = str(e)
            user_identity = getattr(request.state, "user_identity", "anonymous")
            logger.error("request_failed", error=error_msg)
            raise e
        finally:
            duration = time.perf_counter() - start_time
            duration_ms = round(duration * 1000, 2)
            
            logger.info("request_finished", status_code=status_code, duration_ms=duration_ms)

            # Fire off to Delta Lake audit trail (non-blocking if we could use BackgroundTasks, 
            # but doing it here directly for simplicity, Delta Lake append is fast enough for MVP)
            # In production, offload this to a queue.
            audit_logger.log_event(
                request_id=request_id,
                user=user_identity,
                action=f"{request.method} {request.url.path}",
                query_params=str(request.query_params),
                results_count=results_count,
                pii_accessed=pii_accessed,
                duration_ms=duration_ms,
                status_code=status_code,
                error=error_msg,
            )

        return response
