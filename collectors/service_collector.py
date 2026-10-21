"""
Windows Services collector using psutil.

Collects status and start type for all enumerable Windows services.

Uses psutil.win_service_iter() — Windows only.
Gracefully falls back to an empty list on non-Windows or permission errors.
"""
from __future__ import annotations

import logging
import platform
from typing import List

from collectors.base import BaseCollector
from backend.app.schemas.telemetry import ServiceSnapshot

logger = logging.getLogger(__name__)

_IS_WINDOWS = platform.system() == "Windows"


class ServiceCollector(BaseCollector):
    """Collects Windows service status via psutil.win_service_iter()."""

    name = "services"

    def _collect(self) -> List[ServiceSnapshot]:
        if not _IS_WINDOWS:
            raise RuntimeError("ServiceCollector is Windows-only")

        import psutil

        services: List[ServiceSnapshot] = []
        for svc in psutil.win_service_iter():
            try:
                info = svc.as_dict()
                services.append(ServiceSnapshot(
                    name=info.get("name", "unknown"),
                    display_name=info.get("display_name", ""),
                    status=info.get("status", "unknown"),
                    start_type=info.get("start_type", "unknown"),
                ))
            except Exception as exc:
                logger.debug("Skipping service: %s", exc)
                continue

        return services
