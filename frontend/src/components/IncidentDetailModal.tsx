import React, { useState } from 'react';
import {
  X,
  AlertTriangle,
  Shield,
  Bot,
  Terminal,
  CheckCircle2,
  XCircle,
  Play,
  RotateCcw,
  Loader2,
} from 'lucide-react';
import type { Incident, Severity, RiskLevel } from '../types';


interface IncidentDetailModalProps {
  incident: Incident | null;
  isOpen: boolean;
  onClose: () => void;
  onInvestigate: (id: string) => Promise<void>;
  onApproveAction: (actionId: string) => Promise<void>;
  onRejectAction: (actionId: string) => Promise<void>;
  onResolve: (id: string) => Promise<void>;
}

export const IncidentDetailModal: React.FC<IncidentDetailModalProps> = ({
  incident,
  isOpen,
  onClose,
  onInvestigate,
  onApproveAction,
  onRejectAction,
  onResolve,
}) => {
  const [isInvestigating, setIsInvestigating] = useState(false);
  const [actionProcessingId, setActionProcessingId] = useState<string | null>(null);

  if (!isOpen || !incident) return null;

  const handleInvestigate = async () => {
    try {
      setIsInvestigating(true);
      await onInvestigate(incident.id);
    } finally {
      setIsInvestigating(false);
    }
  };

  const handleAction = async (actionId: string, approve: boolean) => {
    try {
      setActionProcessingId(actionId);
      if (approve) {
        await onApproveAction(actionId);
      } else {
        await onRejectAction(actionId);
      }
    } finally {
      setActionProcessingId(null);
    }
  };

  const getSeverityBadgeClass = (sev: Severity) => {
    switch (sev) {
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

  const getRiskBadgeClass = (risk: RiskLevel) => {
    switch (risk) {
      case 'high':
        return 'badge-critical';
      case 'medium':
        return 'badge-medium';
      case 'low':
        return 'badge-low';
      case 'read_only':
        return 'badge-info';
      default:
        return 'badge-neutral';
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-container" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="modal-header">
          <div className="modal-header-info">
            <div className="modal-title-row">
              <span className={`badge ${getSeverityBadgeClass(incident.severity)}`}>
                {incident.severity.toUpperCase()}
              </span>
              <span className="badge badge-status-detected">{incident.status.replace('_', ' ').toUpperCase()}</span>
              <span className="modal-id">ID: {incident.id.slice(0, 8)}</span>
            </div>
            <h2 className="modal-title">{incident.title}</h2>
          </div>
          <button className="btn-icon modal-close-btn" onClick={onClose} title="Close">
            <X size={20} />
          </button>
        </div>

        {/* Content Body */}
        <div className="modal-body">
          {/* Quick Stats Grid */}
          <div className="modal-meta-grid">
            <div className="meta-item">
              <span className="meta-label">Source</span>
              <span className="meta-value">{incident.source}</span>
            </div>
            <div className="meta-item">
              <span className="meta-label">Anomaly Score</span>
              <span className="meta-value text-red">
                {incident.anomaly_score.toFixed(4)}
              </span>
            </div>
            <div className="meta-item">
              <span className="meta-label">Detected At</span>
              <span className="meta-value">
                {new Date(incident.detected_at).toLocaleString()}
              </span>
            </div>
            <div className="meta-item">
              <span className="meta-label">Confidence</span>
              <span className="meta-value">
                {incident.confidence ? `${(incident.confidence * 100).toFixed(0)}%` : 'Pending'}
              </span>
            </div>
          </div>

          {/* Description */}
          {incident.description && (
            <div className="modal-section">
              <h3 className="section-title">Description & Evidence</h3>
              <p className="section-description">{incident.description}</p>
            </div>
          )}

          {/* Multi-Agent Diagnosis */}
          {incident.diagnosis ? (
            <div className="modal-section agent-card">
              <div className="agent-card-header">
                <Bot className="agent-icon icon-cyan" size={18} />
                <span className="agent-title">Diagnosis Agent (Root-Cause Analysis)</span>
                <span className="badge badge-info">
                  {Math.round(incident.diagnosis.confidence * 100)}% Confidence
                </span>
              </div>
              <div className="agent-card-body">
                <div className="mb-3">
                  <span className="text-secondary font-semibold">Probable Root Cause:</span>
                  <p className="root-cause-text">{incident.diagnosis.probable_root_cause}</p>
                </div>
                <div className="mb-3">
                  <span className="text-secondary font-semibold">Technical Analysis:</span>
                  <p className="analysis-text">{incident.diagnosis.technical_analysis}</p>
                </div>
                {incident.diagnosis.affected_subsystems?.length > 0 && (
                  <div className="mb-3">
                    <span className="text-secondary font-semibold">Affected Subsystems:</span>
                    <div className="tag-list">
                      {incident.diagnosis.affected_subsystems.map((sub, idx) => (
                        <span key={idx} className="tag-subsystem">
                          {sub}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {incident.diagnosis.supporting_evidence?.length > 0 && (
                  <div>
                    <span className="text-secondary font-semibold">Supporting Evidence:</span>
                    <ul className="evidence-list">
                      {incident.diagnosis.supporting_evidence.map((ev, idx) => (
                        <li key={idx}>{ev}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="agent-pending-banner">
              <div className="pending-text">
                <Bot size={20} className="text-muted" />
                <span>No AI investigation report generated yet.</span>
              </div>
              <button
                className="btn btn-primary"
                onClick={handleInvestigate}
                disabled={isInvestigating}
              >
                {isInvestigating ? (
                  <>
                    <Loader2 size={16} className="spin-icon" />
                    <span>Running LangGraph Multi-Agent Pipeline...</span>
                  </>
                ) : (
                  <>
                    <Play size={16} />
                    <span>Trigger AI Investigation</span>
                  </>
                )}
              </button>
            </div>
          )}

          {/* Security Assessment & MITRE ATT&CK */}
          {incident.security_assessment && (
            <div className="modal-section agent-card">
              <div className="agent-card-header">
                <Shield className="agent-icon icon-amber" size={18} />
                <span className="agent-title">Security Agent (MITRE ATT&CK & Threat Assessment)</span>
                <span className={`badge ${incident.security_assessment.is_confirmed_threat ? 'badge-critical' : 'badge-neutral'}`}>
                  {incident.security_assessment.threat_classification}
                </span>
              </div>
              <div className="agent-card-body">
                <p className="analysis-text mb-3">{incident.security_assessment.summary}</p>
                {incident.security_assessment.mitre_techniques?.length > 0 && (
                  <div className="mb-3">
                    <span className="text-secondary font-semibold">MITRE ATT&CK Techniques:</span>
                    <div className="tag-list">
                      {incident.security_assessment.mitre_techniques.map((tech, idx) => (
                        <span key={idx} className="badge badge-mitre">
                          {tech}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {incident.security_assessment.containment_required && (
                  <div className="alert-warning-box">
                    <AlertTriangle size={16} />
                    <span>Containment required: Immediate isolation recommended.</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Remediation Actions & Approval Gate */}
          <div className="modal-section">
            <h3 className="section-title">
              <Terminal size={18} className="mr-2 inline" />
              Proposed Remediation Actions
            </h3>
            {incident.actions && incident.actions.length > 0 ? (
              <div className="actions-list">
                {incident.actions.map((act) => (
                  <div key={act.id} className="action-card">
                    <div className="action-card-header">
                      <div className="action-title-group">
                        <span className="action-type-tag">{act.action_type}</span>
                        <span className={`badge ${getRiskBadgeClass(act.risk_level)}`}>
                          Risk: {act.risk_level}
                        </span>
                        <span className={`badge badge-status-${act.status}`}>{act.status}</span>
                      </div>
                      <span className="text-xs text-muted">Proposed by: {act.proposed_by}</span>
                    </div>

                    <p className="action-description">{act.description}</p>

                    {/* Parameters / PowerShell Command Preview */}
                    {act.parameters && (
                      <div className="code-preview-block">
                        <div className="code-header">
                          <span>Action Parameters / Command Preview</span>
                        </div>
                        <pre className="code-content">
                          {JSON.stringify(act.parameters, null, 2)}
                        </pre>
                      </div>
                    )}

                    {/* Rollback Plan */}
                    {act.rollback_plan && (
                      <div className="rollback-box">
                        <RotateCcw size={14} className="text-muted inline mr-1" />
                        <span className="font-semibold text-secondary">Rollback Plan: </span>
                        <span>{act.rollback_plan}</span>
                      </div>
                    )}

                    {/* Action Execution Buttons */}
                    {act.status === 'proposed' && (
                      <div className="action-btn-row">
                        <button
                          className="btn btn-success"
                          disabled={actionProcessingId === act.id}
                          onClick={() => handleAction(act.id, true)}
                        >
                          {actionProcessingId === act.id ? (
                            <Loader2 size={16} className="spin-icon" />
                          ) : (
                            <CheckCircle2 size={16} />
                          )}
                          <span>Approve & Authorize Execution</span>
                        </button>
                        <button
                          className="btn btn-danger-outline"
                          disabled={actionProcessingId === act.id}
                          onClick={() => handleAction(act.id, false)}
                        >
                          <XCircle size={16} />
                          <span>Reject</span>
                        </button>
                      </div>
                    )}

                    {act.status === 'executed' && (
                      <div className="action-executed-pill">
                        <CheckCircle2 size={16} className="text-green" />
                        <span>Action executed successfully</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-text-box">
                {incident.recommended_actions?.length ? (
                  <ul className="evidence-list">
                    {incident.recommended_actions.map((rec, i) => (
                      <li key={i}>{rec}</li>
                    ))}
                  </ul>
                ) : (
                  <span>No remediation actions have been proposed yet. Run AI investigation above.</span>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="modal-footer">
          <div className="modal-footer-left">
            {incident.status !== 'resolved' && (
              <button
                className="btn btn-outline"
                onClick={() => onResolve(incident.id)}
              >
                <CheckCircle2 size={16} />
                <span>Mark as Resolved</span>
              </button>
            )}
          </div>
          <button className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
