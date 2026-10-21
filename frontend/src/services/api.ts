/**
 * API service for communicating with FastAPI backend endpoints.
 */

import type {
  Incident,
  IncidentAction,
  RAGQueryResponse,
  StatsSummary,
  TelemetrySnapshot,
} from '../types';

const API_BASE = '/api';

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errorDetail = `HTTP ${res.status}: ${res.statusText}`;
    try {
      const errJson = await res.json();
      if (errJson.detail) errorDetail = errJson.detail;
    } catch {
      // Keep default text
    }
    throw new Error(errorDetail);
  }
  return res.json();
}

// ── Telemetry & Simulator ───────────────────────────────────────────────────

export async function getTelemetryStatus(): Promise<{
  is_running: boolean;
  interval_seconds: number;
  queue_size: number;
  queue_max_size: number;
  available_collectors: string[];
}> {
  const res = await fetch(`${API_BASE}/telemetry/status`);
  return handleResponse(res);
}

export async function getLatestTelemetry(): Promise<TelemetrySnapshot> {
  const res = await fetch(`${API_BASE}/telemetry/latest`);
  return handleResponse(res);
}

export async function collectTelemetryNow(): Promise<TelemetrySnapshot> {
  const res = await fetch(`${API_BASE}/telemetry/collect-now`, { method: 'POST' });
  return handleResponse(res);
}

export async function getSimulatorScenarios(): Promise<string[]> {
  const res = await fetch(`${API_BASE}/telemetry/simulator/scenarios`);
  return handleResponse(res);
}

export async function runSimulatorScenario(scenarioName: string): Promise<{
  scenario: string;
  duration_seconds: number;
  sample_count: number;
  saved_files: string[];
}> {
  const res = await fetch(`${API_BASE}/telemetry/simulator/run/${scenarioName}`, {
    method: 'POST',
  });
  const data = await handleResponse(res);
  if (Array.isArray(data)) {
    return {
      scenario: scenarioName,
      sample_count: data.length,
      duration_seconds: data.length * 5,
      saved_files: [`sim_${scenarioName}.json`],
    };
  }
  return data as {
    scenario: string;
    duration_seconds: number;
    sample_count: number;
    saved_files: string[];
  };
}

// ── Incidents ───────────────────────────────────────────────────────────────

export async function getIncidents(params?: {
  status?: string;
  severity?: string;
  limit?: number;
  offset?: number;
}): Promise<{ total: number; incidents: Incident[] }> {
  const searchParams = new URLSearchParams();
  if (params?.status && params.status !== 'all') searchParams.set('status', params.status);
  if (params?.severity && params.severity !== 'all') searchParams.set('severity', params.severity);
  if (params?.limit) searchParams.set('limit', String(params.limit));
  if (params?.offset) searchParams.set('offset', String(params.offset));

  const url = `${API_BASE}/incidents${searchParams.toString() ? `?${searchParams.toString()}` : ''}`;
  const res = await fetch(url);
  return handleResponse(res);
}

export async function getIncidentStats(): Promise<StatsSummary> {
  const res = await fetch(`${API_BASE}/incidents/stats/summary`);
  return handleResponse(res);
}

export async function getIncidentById(id: string): Promise<Incident> {
  const res = await fetch(`${API_BASE}/incidents/${id}`);
  return handleResponse(res);
}

export async function updateIncidentStatus(
  id: string,
  status: string,
  reason?: string
): Promise<Incident> {
  const res = await fetch(`${API_BASE}/incidents/${id}/status`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status, reason, actor: 'dashboard_user' }),
  });
  return handleResponse(res);
}

export async function triggerInvestigation(id: string): Promise<Record<string, unknown>> {
  const res = await fetch(`${API_BASE}/incidents/${id}/investigate`, {
    method: 'POST',
  });
  return handleResponse(res);
}

export async function getIncidentActions(id: string): Promise<IncidentAction[]> {
  const res = await fetch(`${API_BASE}/incidents/${id}/actions`);
  return handleResponse(res);
}

export async function executeIncidentAction(
  actionId: string,
  approved: boolean = true
): Promise<IncidentAction> {
  const endpoint = approved ? 'approve' : 'reject';
  const res = await fetch(`${API_BASE}/actions/${actionId}/${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ approved_by: 'dashboard_operator' }),
  });
  return handleResponse(res);
}

// ── RAG Knowledge Base ──────────────────────────────────────────────────────

export async function queryRAG(
  query: string,
  top_k: number = 4,
  category?: string
): Promise<RAGQueryResponse> {
  const res = await fetch(`${API_BASE}/rag/query`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      query,
      top_k,
      category: category && category !== 'all' ? category : undefined,
      min_score: 0.1,
    }),
  });
  return handleResponse(res);
}

export async function getRAGStats(): Promise<{
  collection_name: string;
  total_chunks: number;
  categories: Record<string, number>;
  embedding_model: string;
  embedding_dimension: number;
}> {
  const res = await fetch(`${API_BASE}/rag/stats`);
  return handleResponse(res);
}

export async function reindexRAG(): Promise<{
  status: string;
  chunks_indexed: number;
  elapsed_seconds: number;
  message: string;
}> {
  const res = await fetch(`${API_BASE}/rag/reindex?force=true`, {
    method: 'POST',
  });
  return handleResponse(res);
}
