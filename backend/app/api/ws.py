"""
WebSocket manager and router.

Manages connected dashboard clients and broadcasts events.
Full real-time telemetry and incident push implemented progressively
from Phase 3 (telemetry) through Phase 8 (full dashboard integration).
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Dict, Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)
router = APIRouter()


class ConnectionManager:
    """Manages active WebSocket connections from dashboard clients."""

    def __init__(self) -> None:
        self._connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.add(websocket)
        logger.info("WebSocket client connected. Total: %d", len(self._connections))

    def disconnect(self, websocket: WebSocket) -> None:
        self._connections.discard(websocket)
        logger.info("WebSocket client disconnected. Total: %d", len(self._connections))

    async def broadcast(self, event_type: str, data: dict) -> None:
        """Broadcast a typed event to all connected clients."""
        payload = json.dumps({"type": event_type, "data": data}, default=str)
        dead: Set[WebSocket] = set()
        for ws in self._connections:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self._connections.discard(ws)

    async def send_to(self, websocket: WebSocket, event_type: str, data: dict) -> None:
        """Send an event to a specific client."""
        payload = json.dumps({"type": event_type, "data": data}, default=str)
        await websocket.send_text(payload)

    @property
    def connection_count(self) -> int:
        return len(self._connections)


# Singleton — shared across the application
manager = ConnectionManager()


@router.websocket("/incidents")
async def websocket_incidents(websocket: WebSocket) -> None:
    """
    WebSocket endpoint for real-time incident and telemetry updates.

    Clients connect here to receive:
    - telemetry_snapshot  (Phase 3+)
    - anomaly_detected    (Phase 4+)
    - investigation_update (Phase 7+)
    - action_proposed     (Phase 9+)
    - action_result       (Phase 9+)
    """
    await manager.connect(websocket)
    # Immediately send connection confirmation
    await manager.send_to(websocket, "connected", {
        "message": "Connected to Agentic AI Incident Management",
        "version": "0.1.0",
    })

    # Immediately push latest telemetry snapshot so dashboard populates with zero delay
    try:
        from backend.app.api.telemetry import get_collector_manager
        col_mgr = get_collector_manager()
        snap = col_mgr.get_latest_sync()
        if snap is not None:
            await manager.send_to(websocket, "telemetry_snapshot", snap.model_dump(mode="json"))
    except Exception as snap_err:
        logger.debug("Failed sending initial snapshot on ws connect: %s", snap_err)
    try:
        while True:
            # Keep connection alive; client can send ping messages
            data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            if data == "ping":
                await manager.send_to(websocket, "pong", {})
    except asyncio.TimeoutError:
        # Send server-side keepalive
        try:
            await manager.send_to(websocket, "heartbeat", {})
        except Exception:
            manager.disconnect(websocket)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as exc:
        logger.warning("WebSocket error: %s", exc)
        manager.disconnect(websocket)
