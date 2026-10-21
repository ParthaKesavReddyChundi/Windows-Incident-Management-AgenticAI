import React, { useState } from 'react';
import {
  Bot,
  ExternalLink,
  CheckCircle2,
  Filter,
  Loader2,
  Calendar,
} from 'lucide-react';

import type { Incident, IncidentStatus, Severity } from '../types';

interface IncidentListProps {
  incidents: Incident[];
  selectedIncidentId: string | null;
  onSelectIncident: (id: string) => void;
  onInvestigate: (id: string) => Promise<void>;
  onResolve: (id: string) => Promise<void>;
  isLoading: boolean;
}

export const IncidentList: React.FC<IncidentListProps> = ({
  incidents,
  selectedIncidentId,
  onSelectIncident,
  onInvestigate,
  onResolve,
  isLoading,
}) => {
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [investigatingId, setInvestigatingId] = useState<string | null>(null);

  const filteredIncidents = incidents.filter((inc) => {
    if (statusFilter !== 'all' && inc.status !== statusFilter) return false;
    if (severityFilter !== 'all' && inc.severity !== severityFilter) return false;
    return true;
  });

  const handleInvestigateClick = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    try {
      setInvestigatingId(id);
      await onInvestigate(id);
    } finally {
      setInvestigatingId(null);
    }
  };

  const handleResolveClick = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    await onResolve(id);
  };

  const getSeverityBadgeClass = (severity: Severity) => {
    switch (severity) {
      case 'critical':
        return 'badge-critical';
      case 'high':
        return 'badge-high';
      case 'medium':
        return 'badge-medium';
      case 'low':
        return 'badge-low';
      default:
        return 'badge-neutral';
    }
  };

  const getStatusBadgeClass = (status: IncidentStatus) => {
    switch (status) {
      case 'detected':
        return 'badge-status-detected';
      case 'investigating':
        return 'badge-status-investigating';
      case 'awaiting_approval':
        return 'badge-status-awaiting';
      case 'remediating':
        return 'badge-status-remediating';
      case 'resolved':
        return 'badge-status-resolved';
      case 'dismissed':
        return 'badge-status-dismissed';
      default:
        return 'badge-neutral';
    }
  };

  return (
    <div className="incident-queue-container">
      {/* Filter and Controls Header */}
      <div className="queue-controls-bar">
        <div className="filter-group">
          <Filter size={16} className="text-muted" />
          <span className="filter-label">Status:</span>
          {['all', 'detected', 'investigating', 'awaiting_approval', 'resolved'].map(
            (statusKey) => (
              <button
                key={statusKey}
                className={`filter-pill ${statusFilter === statusKey ? 'active' : ''}`}
                onClick={() => setStatusFilter(statusKey)}
              >
                {statusKey.replace('_', ' ')}
              </button>
            )
          )}
        </div>

        <div className="filter-group">
          <span className="filter-label">Severity:</span>
          {['all', 'critical', 'high', 'medium', 'low'].map((sevKey) => (
            <button
              key={sevKey}
              className={`filter-pill ${severityFilter === sevKey ? 'active' : ''}`}
              onClick={() => setSeverityFilter(sevKey)}
            >
              {sevKey}
            </button>
          ))}
        </div>
      </div>

      {/* Incidents Cards List */}
      <div className="incidents-cards-list">
        {isLoading && incidents.length === 0 ? (
          <div className="loading-state">
            <Loader2 className="spin-icon text-blue" size={32} />
            <p>Loading incident repository...</p>
          </div>
        ) : filteredIncidents.length === 0 ? (
          <div className="empty-state">
            <CheckCircle2 size={40} className="icon-emerald" />
            <h3>No incidents found</h3>
            <p>No system anomalies matching the current filter criteria.</p>
          </div>
        ) : (
          filteredIncidents.map((incident) => {
            const isSelected = incident.id === selectedIncidentId;
            const isCurrentlyInvestigating = investigatingId === incident.id;

            return (
              <div
                key={incident.id}
                className={`incident-card-item ${isSelected ? 'selected' : ''} sev-border-${incident.severity}`}
                onClick={() => onSelectIncident(incident.id)}
              >
                <div className="card-top-row">
                  <div className="card-badges-left">
                    <span className={`badge ${getSeverityBadgeClass(incident.severity)}`}>
                      {incident.severity.toUpperCase()}
                    </span>
                    <span className={`badge ${getStatusBadgeClass(incident.status)}`}>
                      {incident.status.replace('_', ' ').toUpperCase()}
                    </span>
                    <span className="source-tag">source: {incident.source}</span>
                  </div>
                  <div className="card-anomaly-score">
                    Score: <strong>{incident.anomaly_score.toFixed(4)}</strong>
                  </div>
                </div>

                <div className="card-body">
                  <h4 className="incident-card-title">{incident.title}</h4>
                  {incident.description && (
                    <p className="incident-card-desc">{incident.description}</p>
                  )}

                  {incident.root_cause && (
                    <div className="root-cause-snippet">
                      <Bot size={14} className="icon-blue" />
                      <span>
                        <strong>Diagnosis:</strong> {incident.root_cause} (
                        {Math.round((incident.confidence ?? 0) * 100)}% confidence)
                      </span>
                    </div>
                  )}
                </div>

                <div className="card-bottom-row">
                  <div className="timestamp-group">
                    <Calendar size={13} className="text-muted" />
                    <span>{new Date(incident.detected_at).toLocaleString()}</span>
                  </div>

                  <div className="card-actions-group">
                    {incident.status === 'detected' && (
                      <button
                        className="btn-agent"
                        onClick={(e) => handleInvestigateClick(e, incident.id)}
                        disabled={isCurrentlyInvestigating}
                      >
                        {isCurrentlyInvestigating ? (
                          <>
                            <Loader2 size={14} className="spin-icon" />
                            <span>Agents Investigating...</span>
                          </>
                        ) : (
                          <>
                            <Bot size={14} />
                            <span>Investigate</span>
                          </>
                        )}
                      </button>
                    )}

                    {incident.status !== 'resolved' && incident.status !== 'dismissed' && (
                      <button
                        className="btn-resolve"
                        onClick={(e) => handleResolveClick(e, incident.id)}
                      >
                        <CheckCircle2 size={14} />
                        <span>Resolve</span>
                      </button>
                    )}

                    <button
                      className="btn-details"
                      onClick={() => onSelectIncident(incident.id)}
                    >
                      <ExternalLink size={14} />
                      <span>Details</span>
                    </button>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
