/**
 * React hook for managing real-time WebSocket connection to /ws/incidents.
 */

import { useEffect, useRef, useState, useCallback } from 'react';
import type { TelemetrySnapshot } from '../types';

export type ConnectionState = 'connecting' | 'connected' | 'disconnected' | 'error';

export interface WebSocketMessage {
  type: string;
  data: Record<string, unknown>;
}

export function useWebSocket() {
  const [connectionState, setConnectionState] = useState<ConnectionState>('disconnected');
  const [latestTelemetry, setLatestTelemetry] = useState<TelemetrySnapshot | null>(null);
  const [telemetryHistory, setTelemetryHistory] = useState<TelemetrySnapshot[]>([]);
  const [lastEvent, setLastEvent] = useState<WebSocketMessage | null>(null);

  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttemptsRef = useRef<number>(0);

  const connect = useCallback(() => {
    if (socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
      return;
    }

    setConnectionState('connecting');

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // Use window.location.host so Vite proxy or direct host works transparently
    const wsUrl = `${protocol}//${window.location.host}/ws/incidents`;

    try {
      const ws = new WebSocket(wsUrl);
      socketRef.current = ws;

      ws.onopen = () => {
        setConnectionState('connected');
        reconnectAttemptsRef.current = 0;
      };

      ws.onmessage = (event) => {
        try {
          const payload: WebSocketMessage = JSON.parse(event.data);
          setLastEvent(payload);

          if (payload.type === 'telemetry_snapshot' && payload.data) {
            const snap = payload.data as unknown as TelemetrySnapshot;
            setLatestTelemetry(snap);
            setTelemetryHistory((prev) => {
              const updated = [...prev, snap];
              // Keep maximum 30 rolling data points (2.5 minutes at 5s interval)
              return updated.length > 30 ? updated.slice(updated.length - 30) : updated;
            });
          }
        } catch {
          // Ignore JSON parse errors on malformed messages
        }
      };

      ws.onerror = () => {
        setConnectionState('error');
      };

      ws.onclose = () => {
        setConnectionState('disconnected');
        socketRef.current = null;

        // Auto-reconnect with exponential backoff (1s, 2s, 4s, capped at 10s)
        const delay = Math.min(1000 * Math.pow(1.5, reconnectAttemptsRef.current), 10000);
        reconnectAttemptsRef.current += 1;
        reconnectTimeoutRef.current = setTimeout(() => {
          connect();
        }, delay);
      };
    } catch {
      setConnectionState('error');
    }
  }, []);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }
    if (socketRef.current) {
      socketRef.current.close();
      socketRef.current = null;
    }
    setConnectionState('disconnected');
  }, []);

  useEffect(() => {
    connect();
    return () => {
      disconnect();
    };
  }, [connect, disconnect]);

  return {
    connectionState,
    latestTelemetry,
    telemetryHistory,
    lastEvent,
    reconnect: connect,
  };
}
