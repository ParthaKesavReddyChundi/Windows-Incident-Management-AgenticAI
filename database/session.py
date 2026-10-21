"""
database/session.py
===================
Async SQLAlchemy session and engine management using aiosqlite.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import AsyncGenerator

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from config.settings import settings
from database.models import Base

logger = logging.getLogger(__name__)

# Ensure the database directory exists
db_file_path = settings.database_url.replace("sqlite+aiosqlite:///", "")
if db_file_path and not db_file_path.startswith(":memory:"):
    Path(db_file_path).parent.mkdir(parents=True, exist_ok=True)

# Create async engine
engine: AsyncEngine = create_async_engine(
    settings.database_url,
    echo=False,
    future=True,
    connect_args={"check_same_thread": False} if "sqlite" in settings.database_url else {},
)


# Enable SQLite foreign key constraints
@event.listens_for(engine.sync_engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if "sqlite" in settings.database_url:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


# Async session factory
async_session_factory = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def init_db() -> None:
    """Create all database tables if they do not exist."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database initialized successfully at %s", settings.database_url)


async def close_db() -> None:
    """Dispose database connection pool."""
    await engine.dispose()
    logger.info("Database engine disposed")


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for yielding an async database session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
