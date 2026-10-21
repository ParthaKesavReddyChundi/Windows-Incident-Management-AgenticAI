"""
FastAPI application entry point.

Start with:
    .venv\\Scripts\\uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
"""
from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

if sys.platform == "win32":
    import asyncio
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Ensure the project root is on sys.path when running directly
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config.logging_config import setup_logging
from config.settings import settings
from backend.app.api import actions, incidents, rag, telemetry, ws

logger = logging.getLogger(__name__)


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    setup_logging(log_level=settings.app_log_level, logs_dir=settings.logs_dir)
    logger.info("Starting Agentic AI Windows Incident Management backend")
    logger.info("Environment: %s", settings.app_env)
    logger.info("Log level  : %s", settings.app_log_level)

    # Ensure required directories exist
    for d in [settings.logs_dir, settings.reports_dir, settings.models_dir,
              settings.data_raw_dir, settings.data_processed_dir,
              settings.data_simulated_dir, settings.vector_store_path]:
        d.mkdir(parents=True, exist_ok=True)

    # Initialize SQLite database tables
    from database.session import init_db, close_db
    await init_db()

    # Initialize and start telemetry collection loop
    from backend.app.api.telemetry import get_collector_manager, get_anomaly_detector
    col_mgr = get_collector_manager()

    async def _broadcast_live_telemetry(snapshot):
        from backend.app.api.ws import manager
        if manager.connection_count > 0:
            try:
                snap_dict = snapshot.model_dump(mode="json")
                await manager.broadcast("telemetry_snapshot", snap_dict)
            except Exception as b_err:
                logger.debug("Failed broadcasting live telemetry: %s", b_err)

    col_mgr.set_on_snapshot(_broadcast_live_telemetry)
    await col_mgr.start()

    # Load anomaly detector if model artifacts exist
    detector = get_anomaly_detector()
    if detector:
        logger.info("Anomaly detector loaded: threshold=%.6f, device=%s", detector.threshold, detector._device)
    else:
        logger.warning("Anomaly detector artifacts not found; /api/telemetry/detect will be unavailable until trained")

    # Initialize RAG knowledge base
    from backend.app.services.rag_service import RAGService
    rag_svc = RAGService.get_instance()
    rag_svc.initialize(auto_index_if_empty=True)

    yield

    logger.info("Backend shutting down")
    await col_mgr.stop()
    await close_db()


# ── Application ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="Agentic AI Windows Incident Management",
    description=(
        "Multi-agent AI framework for Windows system incident detection, "
        "root-cause analysis, and human-approved remediation."
    ),
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(telemetry.router, prefix="/api/telemetry", tags=["Telemetry"])
app.include_router(incidents.router, prefix="/api/incidents", tags=["Incidents"])
app.include_router(actions.router,   prefix="/api/actions",   tags=["Actions"])
app.include_router(rag.router)
app.include_router(ws.router,        prefix="/ws",            tags=["WebSocket"])


# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/health", tags=["Health"])
async def health_check() -> dict:
    """Basic liveness probe."""
    return {
        "status": "ok",
        "version": "0.1.0",
        "environment": settings.app_env,
    }


@app.get("/", tags=["Health"])
async def root() -> dict:
    """Root redirect information."""
    return {
        "message": "Agentic AI Windows Incident Management API",
        "docs": "/docs",
        "health": "/health",
    }
