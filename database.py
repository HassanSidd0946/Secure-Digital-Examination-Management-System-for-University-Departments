
from __future__ import annotations

import logging
from contextlib import asynccontextmanager, contextmanager
from typing import AsyncGenerator, Generator

from sqlalchemy import create_engine, event, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool, QueuePool

from config import settings

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logger = logging.getLogger("sqlalchemy.engine")

# If SQL_ECHO is enabled, set to DEBUG level for verbose query logging
if settings.SQL_ECHO:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.WARNING)

# Add structured handler if not already configured
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)


# ---------------------------------------------------------------------------
# Engine configuration
# ---------------------------------------------------------------------------

_IS_SQLITE = settings.DATABASE_URL.startswith("sqlite")

# For async support, convert sqlite:// to sqlite+aiosqlite://
_ASYNC_DATABASE_URL = (
    settings.DATABASE_URL.replace("sqlite://", "sqlite+aiosqlite:///")
    if _IS_SQLITE
    else settings.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")
    .replace("mysql://", "mysql+aiomysql://")
)

# Determine pool class: NullPool for SQLite, QueuePool for server databases
_POOL_CLASS = NullPool if _IS_SQLITE else QueuePool

# Create async engine (primary, non-blocking)
# NullPool (SQLite) does not accept pool_size/max_overflow; only QueuePool (PostgreSQL, MySQL, etc) does
_async_engine_kwargs = {
    "echo": settings.SQL_ECHO,
    "poolclass": _POOL_CLASS,
    "connect_args": (
        {"timeout": 30} if _IS_SQLITE else {"server_settings": {"application_name": "crypto_app"}}
    ),
}
if not _IS_SQLITE:
    _async_engine_kwargs["pool_pre_ping"] = True
    _async_engine_kwargs["pool_size"] = settings.DATABASE_POOL_SIZE
    _async_engine_kwargs["max_overflow"] = settings.DATABASE_MAX_OVERFLOW

async_engine = create_async_engine(_ASYNC_DATABASE_URL, **_async_engine_kwargs)

# Create sync engine (fallback for blocking code)
_sync_engine_kwargs = {
    "echo": settings.SQL_ECHO,
    "poolclass": _POOL_CLASS,
    "connect_args": {"check_same_thread": False} if _IS_SQLITE else {},
}
if not _IS_SQLITE:
    _sync_engine_kwargs["pool_pre_ping"] = True
    _sync_engine_kwargs["pool_size"] = settings.DATABASE_POOL_SIZE
    _sync_engine_kwargs["max_overflow"] = settings.DATABASE_MAX_OVERFLOW

sync_engine = create_engine(settings.DATABASE_URL, **_sync_engine_kwargs)


# ---------------------------------------------------------------------------
# Session factories
# ---------------------------------------------------------------------------

# Async session factory (primary for FastAPI endpoints)
AsyncSessionLocal = sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

# Sync session factory (fallback for scripts, migrations, background tasks)
SyncSessionLocal = sessionmaker(
    bind=sync_engine,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


# ---------------------------------------------------------------------------
# FastAPI async dependency
# ---------------------------------------------------------------------------

async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Async FastAPI dependency providing a per-request async session.

    Usage::

        @router.get("/items")
        async def list_items(db: AsyncSession = Depends(get_async_db)):
            result = await db.execute(...)
            return result.scalars().all()
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ---------------------------------------------------------------------------
# Sync fallback dependency (for non-async FastAPI endpoints)
# ---------------------------------------------------------------------------

def get_sync_db() -> Generator[Session, None, None]:
    """
    Sync FastAPI dependency providing a per-request sync session.

    Usage::

        @router.get("/items")
        def list_items(db: Session = Depends(get_sync_db)):
            return db.query(Item).all()

    Prefer get_async_db for new code.
    """
    db = SyncSessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Context managers for scripts and background tasks
# ---------------------------------------------------------------------------

@asynccontextmanager
async def async_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Async context manager for background tasks and scripts.

    Usage::

        async def process_batch():
            async with async_db_session() as db:
                await db.execute(update(User).values(processed=True))
                await db.commit()
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@contextmanager
def sync_db_session() -> Generator[Session, None, None]:
    """
    Sync context manager for background tasks and scripts.

    Usage::

        def process_batch():
            with sync_db_session() as db:
                db.execute(update(User).values(processed=True))
                db.commit()

    Prefer async_db_session for new code.
    """
    db = SyncSessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Database health checks
# ---------------------------------------------------------------------------

async def async_health_check() -> bool:
    """Return True if the async database is reachable."""
    try:
        async with async_engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"Async DB health check failed: {e}")
        return False


def sync_health_check() -> bool:
    """Return True if the sync database is reachable."""
    try:
        with sync_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"Sync DB health check failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Schema initialization (DEPRECATED — use Alembic instead)
# ---------------------------------------------------------------------------

def init_db() -> None:
    """
    Create all tables declared on Base.

    ⚠️  DEPRECATED: Use Alembic for proper schema versioning in production.
    This is only suitable for local development and testing.

    See: https://alembic.sqlalchemy.org/
    """
    logger.warning(
        "init_db() is deprecated. Use Alembic migrations for schema management. "
        "See: https://alembic.sqlalchemy.org/"
    )
    from models import Base  # import here to avoid circular imports

    with sync_engine.begin() as conn:
        Base.metadata.create_all(bind=conn)
    logger.info("Database schema initialized (deprecated method)")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# Backward-compatibility aliases for main.py and routers
engine = sync_engine  # Used in lifespan.shutdown for cleanup
health_check = sync_health_check  # Used in /health endpoint
get_db = get_sync_db  # Used in routers/auth.py
SessionLocal = SyncSessionLocal  # Used in routers/files.py

__all__ = [
    # Engines
    "async_engine",
    "sync_engine",
    "engine",  # backward-compat alias
    # Session factories
    "AsyncSessionLocal",
    "SyncSessionLocal",
    "SessionLocal",  # backward-compat alias
    # FastAPI dependencies
    "get_async_db",
    "get_sync_db",
    "get_db",  # backward-compat alias
    # Context managers
    "async_db_session",
    "sync_db_session",
    # Health checks
    "async_health_check",
    "sync_health_check",
    "health_check",  # backward-compat alias
    # Schema (deprecated)
    "init_db",
]
