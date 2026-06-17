"""
main.py — Entry point for the Secure Examination API.

Improvements
------------
1.  Lifespan handler       — DB init moved from module-level into startup event;
                             avoids side-effects on import (breaks pytest, Alembic, etc.).
2.  Env-driven CORS        — origins read from settings instead of hard-coded localhost;
                             safe for staging/production without touching source.
3.  Structured logging     — JSON-friendly format with timestamps; level from settings.
4.  Health check           — now queries the DB so a "green" response means the whole
                             stack is up, not just the Python process.
5.  Security headers       — middleware adds X-Content-Type-Options, X-Frame-Options,
                             and Strict-Transport-Security on every response.
6.  Global exception handler — unhandled 500s are logged and return a safe generic body
                               instead of leaking tracebacks to the client.
7.  `openapi_url` guard    — OpenAPI schema endpoint disabled in production.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from config import settings
from database import engine, health_check, init_db
from routers import auth, file_router, communication

# ---------------------------------------------------------------------------
# Logging  (Fix #3)
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Security-headers middleware  (Fix #5)
# ---------------------------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"]  = "nosniff"
        response.headers["X-Frame-Options"]         = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response


# ---------------------------------------------------------------------------
# Lifespan  (Fix #1)
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info("startup: initialising database tables")
    init_db()                       # create_all wrapped in database.py
    logger.info("startup: complete")
    yield
    logger.info("shutdown: closing DB connections")
    engine.dispose()


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title       = "Secure Digital Examination Management System",
    description = "Hybrid RSA-AES Secure Communication System for University Departments.",
    version     = "1.0.0",
    lifespan    = lifespan,
    # Fix #7 — hide schema in production
    openapi_url = "/openapi.json" if settings.DEBUG else None,
    docs_url    = "/docs"         if settings.DEBUG else None,
    redoc_url   = "/redoc"        if settings.DEBUG else None,
)

# Fix #5 — security headers on every response
app.add_middleware(SecurityHeadersMiddleware)

# Fix #2 — origins from config, not hard-coded
app.add_middleware(
    CORSMiddleware,
    allow_origins     = settings.CORS_ORIGINS,   # e.g. ["http://localhost:3000"]
    allow_credentials = True,
    allow_methods     = ["GET", "POST", "DELETE"],   # explicit, not wildcard
    allow_headers     = ["Authorization", "Content-Type"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(auth)
app.include_router(file_router)
app.include_router(communication.router)


# ---------------------------------------------------------------------------
# Global exception handler  (Fix #6)
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("unhandled-error", extra={"path": request.url.path})
    return JSONResponse(
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
        content     = {"detail": "An internal error occurred."},
    )


# ---------------------------------------------------------------------------
# Health check  (Fix #4)
# ---------------------------------------------------------------------------

@app.get("/health", tags=["System"])
def health():
    db_ok = health_check()          # SELECT 1 from database.py
    if not db_ok:
        return JSONResponse(
            status_code = status.HTTP_503_SERVICE_UNAVAILABLE,
            content     = {"status": "db-unreachable"},
        )
    return {"status": "ok", "db": "ok"}