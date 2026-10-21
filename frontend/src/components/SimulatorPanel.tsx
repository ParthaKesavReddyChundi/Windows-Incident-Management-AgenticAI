import React, { useState } from 'react';
import {
  Zap,
  Play,
  Loader2,
  CheckCircle2,
  AlertCircle,
  Cpu,
  Database,
  HardDrive,
  Radio,
  Server,
  FileWarning,
  RefreshCw,
} from 'lucide-react';
import { runSimulatorScenario, collectTelemetryNow } from '../services/api';

interface ScenarioMeta {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  durationSeconds: number;
  icon: React.ReactNode;
}

const SCENARIOS: ScenarioMeta[] = [
  {
    id: 'cpu_overload',
    name: 'CPU Core Starvation',
    description:
      'Spins high-utilization compute threads across CPU cores, driving processor usage above 90% to trigger deep learning anomaly detection.',
    category: 'Processor',
    severity: 'high',
    durationSeconds: 15,
    icon: <Cpu size={22} className="text-orange-400" />,
  },
  {
    id: 'memory_pressure',
    name: 'RAM Pressure & Leak',
    description:
      'Performs progressive memory buffer allocation simulating an uncontrolled memory leak until memory pressure crosses the critical threshold.',
    category: 'Memory',
    severity: 'high',
    durationSeconds: 15,
    icon: <Database size={22} className="text-purple-400" />,
  },
  {
    id: 'disk_pressure',
    name: 'Disk Thrashing & I/O Burst',
    description:
      'Executes high-frequency read/write IOPS operations to saturate disk queue length and test Windows storage telemetry detection.',
    category: 'Storage',
    severity: 'medium',
    durationSeconds: 15,
    icon: <HardDrive size={22} className="text-yellow-400" />,
  },
  {
    id: 'service_failure',
    name: 'Windows Service Crash',
    description:
      'Simulates abnormal termination of a critical Windows system service (Spooler / EventLog), testing automated service health monitoring.',
    category: 'Services',
    severity: 'critical',
    durationSeconds: 10,
    icon: <Server size={22} className="text-red-400" />,
  },
  {
    id: 'network_anomaly',
    name: 'Network Flood & DoS Burst',
    description:
      'Generates rapid outbound/inbound socket connections and high-volume byte streams mimicking a network DoS or external data exfiltration.',
    category: 'Network',
    severity: 'high',
    durationSeconds: 15,
    icon: <Radio size={22} className="text-blue-400" />,
  },
  {
    id: 'app_failure',
    name: 'Application Exception Storm',
    description:
      'Injects simulated unhandled process exceptions and Windows Event Log error events (Event ID 1000/1001) for root cause analysis.',
    category: 'Application',
    severity: 'medium',
    durationSeconds: 10,
    icon: <FileWarning size={22} className="text-pink-400" />,
  },
];

export const SimulatorPanel: React.FC = () => {
  const [runningScenario, setRunningScenario] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<{
    scenario: string;
    sample_count: number;
    duration_seconds: number;
    message?: string;
  } | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isCollecting, setIsCollecting] = useState(false);

  const handleRunScenario = async (scenarioId: string) => {
    try {
      setRunningScenario(scenarioId);
      setErrorMsg(null);
      const res = await runSimulatorScenario(scenarioId);
      setLastResult({
        scenario: res.scenario,
        sample_count: res.sample_count,
        duration_seconds: res.duration_seconds,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setErrorMsg(`Failed to run scenario ${scenarioId}: ${msg}`);
    } finally {
      setRunningScenario(null);
    }
  };

  const handleCollectNow = async () => {
    try {
      setIsCollecting(true);
      await collectTelemetryNow();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setErrorMsg(`Telemetry collection failed: ${msg}`);
    } finally {
      setIsCollecting(false);
    }
  };

  return (
    <div className="simulator-panel-container">
      {/* Header Banner */}
      <div className="simulator-header">
        <div className="simulator-header-text">
          <div className="simulator-badge">
            <Zap size={16} />
            <span>Synthetic Incident Generator</span>
          </div>
          <h2 className="simulator-title">Windows Incident Simulator</h2>
          <p className="simulator-subtitle">
            Inject controlled synthetic system anomalies to evaluate PyTorch Autoencoder
            detection fidelity, trigger LangGraph multi-agent investigations, and test automated
            remediation workflows safely in real time.
          </p>
        </div>
        <div className="simulator-actions">
          <button
            className="btn btn-outline"
            onClick={handleCollectNow}
            disabled={isCollecting}
          >
            <RefreshCw size={16} className={isCollecting ? 'spin-icon' : ''} />
            <span>Collect Snapshot Now</span>
          </button>
        </div>
      </div>

      {/* Execution Feedback Notification */}
      {lastResult && (
        <div className="simulator-notification notification-success">
          <CheckCircle2 size={18} className="text-green flex-shrink-0" />
          <div className="notification-content">
            <span className="font-semibold">Scenario Completed Successfully: </span>
            <span>
              Generated <strong>{lastResult.sample_count}</strong> telemetry snapshots across{' '}
              <strong>{lastResult.duration_seconds}s</strong> for{' '}
              <code>{lastResult.scenario}</code>. Anomaly flags pushed to live queue.
            </span>
          </div>
          <button
            className="btn-text-close"
            onClick={() => setLastResult(null)}
          >
            &times;
          </button>
        </div>
      )}

      {errorMsg && (
        <div className="simulator-notification notification-error">
          <AlertCircle size={18} className="text-red flex-shrink-0" />
          <div className="notification-content">
            <span>{errorMsg}</span>
          </div>
          <button
            className="btn-text-close"
            onClick={() => setErrorMsg(null)}
          >
            &times;
          </button>
        </div>
      )}

      {/* Scenarios Grid */}
      <div className="scenario-grid">
        {SCENARIOS.map((sc) => {
          const isRunning = runningScenario === sc.id;
          return (
            <div key={sc.id} className="scenario-card">
              <div className="scenario-card-header">
                <div className="scenario-icon-wrapper">{sc.icon}</div>
                <div className="scenario-badges">
                  <span className="tag-category">{sc.category}</span>
                  <span className={`badge badge-${sc.severity}`}>
                    {sc.severity.toUpperCase()}
                  </span>
                </div>
              </div>

              <h3 className="scenario-name">{sc.name}</h3>
              <p className="scenario-desc">{sc.description}</p>

              <div className="scenario-footer">
                <span className="scenario-duration">
                  Est. Duration: ~{sc.durationSeconds}s
                </span>
                <button
                  className="btn btn-primary btn-sm"
                  onClick={() => handleRunScenario(sc.id)}
                  disabled={runningScenario !== null}
                >
                  {isRunning ? (
                    <>
                      <Loader2 size={14} className="spin-icon" />
                      <span>Simulating...</span>
                    </>
                  ) : (
                    <>
                      <Play size={14} />
                      <span>Inject Incident</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
