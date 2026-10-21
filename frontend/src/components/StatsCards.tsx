import React from 'react';
import {
  Cpu,
  Database,
  HardDrive,
  Network,
  AlertOctagon,
  Clock,
} from 'lucide-react';
import type { StatsSummary, TelemetrySnapshot } from '../types';

interface StatsCardsProps {
  telemetry: TelemetrySnapshot | null;
  stats: StatsSummary | null;
}

export const StatsCards: React.FC<StatsCardsProps> = ({ telemetry, stats }) => {
  const cpuPercent = telemetry?.cpu?.percent ?? telemetry?.cpu?.cpu_percent ?? 0;
  const memPercent = telemetry?.memory?.percent ?? 0;
  const memUsedGB = telemetry?.memory?.used_bytes
    ? (telemetry.memory.used_bytes / 1024 ** 3).toFixed(1)
    : '0';
  const memTotalGB = telemetry?.memory?.total_bytes
    ? (telemetry.memory.total_bytes / 1024 ** 3).toFixed(1)
    : '0';

  const rawDiskWrite = telemetry?.disks
    ? telemetry.disks.reduce((sum, d) => sum + (d.write_bytes_sec ?? 0), 0)
    : (telemetry?.disk?.write_bytes_per_sec ?? 0);
  const rawDiskRead = telemetry?.disks
    ? telemetry.disks.reduce((sum, d) => sum + (d.read_bytes_sec ?? 0), 0)
    : (telemetry?.disk?.read_bytes_per_sec ?? 0);

  const diskWriteMB = (rawDiskWrite / 1024 ** 2).toFixed(1);
  const diskReadMB = (rawDiskRead / 1024 ** 2).toFixed(1);

  const rawNetSent = telemetry?.networks
    ? telemetry.networks.reduce((sum, n) => sum + (n.bytes_sent_sec ?? 0), 0)
    : (telemetry?.network?.bytes_sent_per_sec ?? 0);
  const rawNetRecv = telemetry?.networks
    ? telemetry.networks.reduce((sum, n) => sum + (n.bytes_recv_sec ?? 0), 0)
    : (telemetry?.network?.bytes_recv_per_sec ?? 0);

  const netSentKB = (rawNetSent / 1024).toFixed(0);
  const netRecvKB = (rawNetRecv / 1024).toFixed(0);

  return (
    <div className="stats-grid">
      {/* Active Incidents Card */}
      <div className="stat-card border-l-red">
        <div className="stat-header">
          <span className="stat-label">Active Incidents</span>
          <AlertOctagon className="stat-icon icon-red" size={20} />
        </div>
        <div className="stat-value-group">
          <span className="stat-value">{stats?.active ?? stats?.active_incidents ?? 0}</span>
          <span className="stat-subtext">Total: {stats?.total ?? stats?.total_incidents ?? 0}</span>
        </div>
        <div className="stat-footer">
          <span className="badge badge-critical">
            Critical: {stats?.by_severity?.critical ?? stats?.severity_breakdown?.critical ?? 0}
          </span>
          <span className="badge badge-high">
            High: {stats?.by_severity?.high ?? stats?.severity_breakdown?.high ?? 0}
          </span>
        </div>
      </div>

      {/* CPU Utilization Card */}
      <div className={`stat-card ${cpuPercent > 80 ? 'border-l-red' : 'border-l-blue'}`}>
        <div className="stat-header">
          <span className="stat-label">CPU Utilization</span>
          <Cpu className="stat-icon icon-blue" size={20} />
        </div>
        <div className="stat-value-group">
          <span className="stat-value">{cpuPercent.toFixed(1)}%</span>
          <span className="stat-subtext">
            {telemetry?.cpu?.cpu_count_logical ?? telemetry?.cpu?.per_core?.length ?? 0} Logical Cores
          </span>
        </div>
        <div className="progress-bar-bg">
          <div
            className={`progress-bar-fill ${
              cpuPercent > 85 ? 'fill-red' : cpuPercent > 70 ? 'fill-amber' : 'fill-blue'
            }`}
            style={{ width: `${Math.min(cpuPercent, 100)}%` }}
          />
        </div>
      </div>

      {/* Memory Pressure Card */}
      <div className={`stat-card ${memPercent > 80 ? 'border-l-red' : 'border-l-emerald'}`}>
        <div className="stat-header">
          <span className="stat-label">RAM Utilization</span>
          <Database className="stat-icon icon-emerald" size={20} />
        </div>
        <div className="stat-value-group">
          <span className="stat-value">{memPercent.toFixed(1)}%</span>
          <span className="stat-subtext">
            {memUsedGB} / {memTotalGB} GB
          </span>
        </div>
        <div className="progress-bar-bg">
          <div
            className={`progress-bar-fill ${
              memPercent > 85 ? 'fill-red' : memPercent > 70 ? 'fill-amber' : 'fill-emerald'
            }`}
            style={{ width: `${Math.min(memPercent, 100)}%` }}
          />
        </div>
      </div>

      {/* Storage Disk I/O Card */}
      <div className="stat-card border-l-purple">
        <div className="stat-header">
          <span className="stat-label">Disk Throughput</span>
          <HardDrive className="stat-icon icon-purple" size={20} />
        </div>
        <div className="stat-value-group">
          <span className="stat-value">{diskWriteMB} <span className="stat-unit">MB/s W</span></span>
          <span className="stat-subtext">{diskReadMB} MB/s R</span>
        </div>
        <div className="stat-mini-metrics">
          <span>Read: {diskReadMB} MB/s</span>
          <span>Write: {diskWriteMB} MB/s</span>
        </div>
      </div>

      {/* Network Bandwidth Card */}
      <div className="stat-card border-l-cyan">
        <div className="stat-header">
          <span className="stat-label">Network Throughput</span>
          <Network className="stat-icon icon-cyan" size={20} />
        </div>
        <div className="stat-value-group">
          <span className="stat-value">{netSentKB} <span className="stat-unit">KB/s Out</span></span>
          <span className="stat-subtext">{netRecvKB} KB/s In</span>
        </div>
        <div className="stat-mini-metrics">
          <span>
            Sockets: {telemetry?.networks ? telemetry.networks.reduce((sum, n) => sum + (n.connections_count ?? 0), 0) : (telemetry?.network?.active_connections_count ?? 'N/A')}
          </span>
          <span className="flex items-center gap-1">
            <Clock size={12} />
            {telemetry?.timestamp ? new Date(telemetry.timestamp).toLocaleTimeString() : 'N/A'}
          </span>
        </div>
      </div>
    </div>
  );
};
