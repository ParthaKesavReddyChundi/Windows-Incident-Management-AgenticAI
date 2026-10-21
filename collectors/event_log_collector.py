"""
Windows Event Log collector using pywin32 (win32evtlog).

Reads recent entries from System, Application, and (optionally) Security
Event Logs. Security log requires elevated privileges and may be skipped.

SECURITY NOTE:
  - Event log content is treated as untrusted data.
  - Log messages are never executed or passed to an LLM as instructions.
  - Only metadata fields are parsed; raw messages are stored as text only.
"""
from __future__ import annotations

import logging
import platform
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_IS_WINDOWS = platform.system() == "Windows"

# Maximum entries to read per log channel per call
_MAX_ENTRIES_PER_LOG = 50

# Event log channels to read
_LOG_CHANNELS = ["System", "Application"]
_PRIVILEGED_CHANNELS = ["Security"]  # Requires admin — tried but skipped on failure

# Event types mapping
_EVENT_TYPES: Dict[int, str] = {
    1: "ERROR",
    2: "WARNING",
    4: "INFORMATION",
    8: "AUDIT_SUCCESS",
    16: "AUDIT_FAILURE",
}


def _parse_event(event: Any) -> Optional[Dict[str, Any]]:
    """Parse a win32evtlog event record into a plain dict."""
    try:
        evt_type = _EVENT_TYPES.get(event.EventType, "UNKNOWN")
        time_generated = event.TimeGenerated
        # win32evtlog returns a pywintypes.datetime — convert to standard datetime
        if hasattr(time_generated, "timestamp"):
            ts = datetime.fromtimestamp(time_generated.timestamp(), tz=timezone.utc)
        else:
            ts = datetime.now(tz=timezone.utc)

        return {
            "record_number": event.RecordNumber,
            "event_id": event.EventID & 0xFFFF,  # Strip qualifier bits
            "event_type": evt_type,
            "source": event.SourceName,
            "timestamp": ts.isoformat(),
            "category": event.EventCategory,
        }
    except Exception as exc:
        logger.debug("Failed to parse event record: %s", exc)
        return None


class EventLogCollector:
    """
    Reads recent Windows Event Log entries via pywin32.

    This class does NOT subclass BaseCollector because it collects from
    multiple channels and returns a dict of channel → entries, rather
    than a single typed snapshot.
    """

    name = "event_log"

    def __init__(self) -> None:
        self._available: bool = _IS_WINDOWS
        self._last_error: Optional[str] = None
        self._last_latency_ms: float = 0.0
        self._collect_count: int = 0

    def collect(self) -> Optional[Dict[str, List[Dict[str, Any]]]]:
        """Return {channel: [event_dict, ...]} or None if unavailable."""
        if not _IS_WINDOWS:
            self._available = False
            self._last_error = "Not running on Windows"
            return None

        import time
        t0 = time.perf_counter()

        try:
            import win32evtlog
            import win32con

            result: Dict[str, List[Dict[str, Any]]] = {}
            # Standard non-privileged channels by default
            channels = list(_LOG_CHANNELS)

            for channel in channels:
                entries: List[Dict[str, Any]] = []
                try:
                    handle = win32evtlog.OpenEventLog(None, channel)
                    flags = (
                        win32evtlog.EVENTLOG_BACKWARDS_READ
                        | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    )
                    events = win32evtlog.ReadEventLog(handle, flags, 0)
                    for event in (events or [])[:_MAX_ENTRIES_PER_LOG]:
                        parsed = _parse_event(event)
                        if parsed:
                            entries.append(parsed)
                    win32evtlog.CloseEventLog(handle)
                    result[channel] = entries
                except Exception as exc:
                    logger.debug("[event_log] Failed to read %s log: %s", channel, exc)
                    continue

            self._available = True
            self._last_error = None
            self._collect_count += 1
            return result if result else None

        except ImportError:
            self._available = False
            self._last_error = "pywin32 not installed"
            return None
        except Exception as exc:
            self._available = False
            self._last_error = str(exc)
            logger.warning("[event_log] Collection failed: %s", exc)
            return None
        finally:
            self._last_latency_ms = (time.perf_counter() - t0) * 1000

    @property
    def is_available(self) -> bool:
        return self._available

    @property
    def last_error(self) -> Optional[str]:
        return self._last_error

    @property
    def last_latency_ms(self) -> float:
        return self._last_latency_ms

    @property
    def collect_count(self) -> int:
        return self._collect_count
