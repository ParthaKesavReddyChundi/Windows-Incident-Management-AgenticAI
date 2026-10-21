import React from 'react';
import {
  Shield,
  Activity,
  AlertTriangle,
  Radio,
  RefreshCw,
  Cpu,
  BookOpen,
  Zap,
} from 'lucide-react';
import type { ConnectionState, TelemetrySnapshot } from '../types';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  connectionState: ConnectionState;
  latestTelemetry: TelemetrySnapshot | null;
  onRefreshTelemetry: () => void;
  isRefreshing: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  connectionState,
  latestTelemetry,
  onRefreshTelemetry,
  isRefreshing,
}) => {
  const isAnomaly = latestTelemetry?.is_anomaly ?? false;

  return (
    <header className="navbar-container">
      <div className="navbar-brand">
        <div className="brand-logo">
          <Shield className="brand-icon" size={24} />
        </div>
        <div>
          <h1 className="brand-title">Agentic AI Windows Incident Manager</h1>
          <p className="brand-subtitle">Autonomous Detection, Root-Cause Analysis & Remediation</p>
        </div>
      </div>

      <nav className="navbar-nav">
        <button
          className={`nav-tab ${activeTab === 'dashboard' ? 'active' : ''}`}
          onClick={() => setActiveTab('dashboard')}
        >
          <Activity size={18} />
          <span>Live Telemetry</span>
        </button>
        <button
          className={`nav-tab ${activeTab === 'incidents' ? 'active' : ''}`}
          onClick={() => setActiveTab('incidents')}
        >
          <AlertTriangle size={18} />
          <span>Incidents Queue</span>
        </button>
        <button
          className={`nav-tab ${activeTab === 'knowledge' ? 'active' : ''}`}
          onClick={() => setActiveTab('knowledge')}
        >
          <BookOpen size={18} />
          <span>RAG Knowledge Base</span>
        </button>
        <button
          className={`nav-tab ${activeTab === 'simulator' ? 'active' : ''}`}
          onClick={() => setActiveTab('simulator')}
        >
          <Zap size={18} />
          <span>Simulator</span>
        </button>
      </nav>

      <div className="navbar-status">
        {/* Anomaly Badge */}
        {isAnomaly ? (
          <div className="status-pill status-danger pulse-animation">
            <AlertTriangle size={14} />
            <span>ANOMALY FLAGGED</span>
          </div>
        ) : (
          <div className="status-pill status-normal">
            <Cpu size={14} />
            <span>SYSTEM NORMAL</span>
          </div>
        )}

        {/* WebSocket Connection State */}
        <div
          className={`status-pill ws-pill ${
            connectionState === 'connected'
              ? 'status-connected'
              : connectionState === 'connecting'
              ? 'status-connecting'
              : 'status-disconnected'
          }`}
          title={`WebSocket Status: ${connectionState}`}
        >
          <Radio size={14} className={connectionState === 'connected' ? 'pulse-icon' : ''} />
          <span className="capitalize">{connectionState}</span>
        </div>

        {/* Manual Refresh Button */}
        <button
          className="btn-icon"
          onClick={onRefreshTelemetry}
          disabled={isRefreshing}
          title="Collect Telemetry Now"
        >
          <RefreshCw size={16} className={isRefreshing ? 'spin-icon' : ''} />
        </button>
      </div>
    </header>
  );
};
