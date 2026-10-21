/**
 * TypeScript type definitions for the Windows Incident Management Dashboard.
 */

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type IncidentStatus =
  | 'detected'
  | 'investigating'
  | 'awaiting_approval'
  | 'remediating'
  | 'mitigated'
  | 'resolved'
  | 'dismissed';

export type RiskLevel = 'read_only' | 'low' | 'medium' | 'high';

export type ActionStatus =
  | 'proposed'
  | 'approved'
  | 'rejected'
  | 'executing'
  | 'executed'
  | 'failed';

export type ConnectionState = 'connecting' | 'connected' | 'disconnected' | 'error';


export interface TelemetrySnapshot {
  snapshot_id?: string;
  timestamp: string;
  source: string;
  is_anomaly?: boolean | null;
  collection_latency_ms?: number;
  cpu?: {
    percent?: number;
    cpu_percent?: number;
    per_core?: number[];
    cpu_percent_per_core?: number[];
    freq_mhz?: number;
    cpu_freq_current_mhz?: number;
    cpu_count_logical?: number;
  };
  memory?: {
    total_bytes: number;
    available_bytes: number;
    used_bytes: number;
    percent: number;
    swap_percent?: number;
  };
  disks?: Array<{
    device: string;
    mountpoint: string;
    total_bytes?: number;
    used_bytes?: number;
    free_bytes?: number;
    percent?: number;
    read_bytes_sec?: number;
    write_bytes_sec?: number;
  }>;
  disk?: {
    partitions?: Array<{
      device: string;
      mountpoint: string;
      percent: number;
      free_bytes: number;
    }>;
    read_bytes_per_sec?: number;
    write_bytes_per_sec?: number;
  };
  networks?: Array<{
    interface: string;
    bytes_sent_sec?: number;
    bytes_recv_sec?: number;
    packets_sent_sec?: number;
    packets_recv_sec?: number;
    connections_count?: number;
  }>;
  network?: {
    bytes_sent_per_sec?: number;
    bytes_recv_per_sec?: number;
    packets_sent_per_sec?: number;
    packets_recv_per_sec?: number;
    active_connections_count?: number;
  };
  top_processes?: Array<{
    pid: number;
    name: string;
    cpu_percent: number;
    memory_mb?: number;
    status?: string;
    username?: string;
  }>;
  processes?: {
    process_count?: number;
    top_processes_by_cpu?: Array<{
      pid: number;
      name: string;
      cpu_percent: number;
      memory_percent?: number;
      memory_rss_mb?: number;
      num_threads?: number;
      status?: string;
    }>;
  };
  services?: any;
  event_log?: {
    system_error_count?: number;
    application_error_count?: number;
    recent_events?: Array<{
      time_generated: string;
      event_id: number;
      source_name: string;
      event_type: string;
      message: string;
    }>;
  };
}

export interface AnomalyDetectionResult {
  anomaly_score: number;
  threshold: number;
  is_anomaly: boolean;
  severity: Severity;
  deviant_features: Array<{
    feature: string;
    error: number;
    actual_value?: number;
    expected_value?: number;
  }>;
}

export interface DiagnosisData {
  probable_root_cause: string;
  confidence: number;
  affected_subsystems: string[];
  supporting_evidence: string[];
  technical_analysis: string;
  uncertainty_notes?: string;
}

export interface SecurityData {
  threat_classification: string;
  risk_level: Severity;
  mitre_techniques: string[];
  threat_indicators: string[];
  is_confirmed_threat: boolean;
  containment_required: boolean;
  summary: string;
}

export interface RemediationProposal {
  action_type: string;
  target: string;
  parameters: Record<string, unknown>;
  description: string;
  risk_level: RiskLevel;
  command_template: string;
  expected_impact: string;
  verification_step: string;
  rollback_plan: string;
  requires_human_approval: boolean;
}

export interface RemediationData {
  executive_summary: string;
  proposed_actions: RemediationProposal[];
  estimated_resolution_time_sec?: number;
}

export interface IncidentAction {
  id: string;
  incident_id: string;
  action_type: string;
  description: string;
  risk_level: RiskLevel;
  status: ActionStatus;
  parameters?: Record<string, unknown>;
  rollback_plan?: string;
  proposed_by: string;
  approved_by?: string;
  execution_result?: Record<string, unknown>;
  created_at: string;
  executed_at?: string;
}

export interface AuditLogItem {
  id: string;
  incident_id: string;
  timestamp: string;
  actor: string;
  action: string;
  details?: Record<string, unknown>;
}

export interface Incident {
  id: string;
  title: string;
  description?: string;
  severity: Severity;
  status: IncidentStatus;
  source: string;
  anomaly_score: number;
  root_cause?: string;
  confidence?: number;
  recommended_actions?: string[];
  diagnosis?: DiagnosisData;
  security_assessment?: SecurityData;
  detected_at: string;
  updated_at: string;
  resolved_at?: string;
  actions?: IncidentAction[];
  audit_logs?: AuditLogItem[];
}

export interface StatsSummary {
  total: number;
  active: number;
  resolved: number;
  dismissed: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  total_incidents?: number;
  active_incidents?: number;
  resolved_incidents?: number;
  dismissed_incidents?: number;
  severity_breakdown?: Record<string, number>;
  status_breakdown?: Record<string, number>;
}

export interface RAGSearchResult {
  chunk_id: string;
  source_file: string;
  title: string;
  section: string;
  category: string;
  content: string;
  similarity_score: number;
  distance: number;
  metadata?: Record<string, unknown>;
}

export interface RAGQueryResponse {
  query: string;
  total_results: number;
  results: RAGSearchResult[];
  retrieval_time_ms: number;
}
