import React from 'react';
import { Activity, Server, AlertCircle } from 'lucide-react';
import type { TelemetrySnapshot } from '../types';

interface TelemetryChartsProps {
  telemetry: TelemetrySnapshot | null;
  history: TelemetrySnapshot[];
}

export const TelemetryCharts: React.FC<TelemetryChartsProps> = ({
  telemetry,
  history,
}) => {
  // Generate SVG path for rolling CPU %
  const renderLineChart = (
    data: number[],
    color: string,
    fillGradientId: string,
    maxY: number = 100
  ) => {
    if (data.length < 2) {
      return (
        <div className="chart-empty">Collecting live telemetry stream...</div>
      );
    }

    const width = 500;
    const height = 140;
    const padding = 15;

    const points = data.map((val, idx) => {
      const x = padding + (idx / (data.length - 1)) * (width - 2 * padding);
      const normalizedY = Math.min(Math.max(val, 0), maxY);
      const y = height - padding - (normalizedY / maxY) * (height - 2 * padding);
      return { x, y };
    });

    const pathD = points.reduce(
      (acc, curr, idx) =>
        idx === 0 ? `M ${curr.x} ${curr.y}` : `${acc} L ${curr.x} ${curr.y}`,
      ''
    );

    const areaD = `${pathD} L ${points[points.length - 1].x} ${
      height - padding
    } L ${points[0].x} ${height - padding} Z`;

    const latestVal = data[data.length - 1] ?? 0;

    return (
      <div className="chart-wrapper">
        <svg viewBox={`0 0 ${width} ${height}`} className="sparkline-svg">
          <defs>
            <linearGradient id={fillGradientId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity="0.4" />
              <stop offset="100%" stopColor={color} stopOpacity="0.0" />
            </linearGradient>
          </defs>
          {/* Subtle grid lines */}
          <line
            x1={padding}
            y1={padding}
            x2={width - padding}
            y2={padding}
            stroke="#2e303a"
            strokeDasharray="4 4"
          />
          <line
            x1={padding}
            y1={height / 2}
            x2={width - padding}
            y2={height / 2}
            stroke="#2e303a"
            strokeDasharray="4 4"
          />
          <line
            x1={padding}
            y1={height - padding}
            x2={width - padding}
            y2={height - padding}
            stroke="#2e303a"
          />

          {/* Shaded Area */}
          <path d={areaD} fill={`url(#${fillGradientId})`} />
          {/* Stroke Line */}
          <path
            d={pathD}
            fill="none"
            stroke={color}
            strokeWidth="2.5"
            strokeLinecap="round"
          />

          {/* Current Value Point */}
          <circle
            cx={points[points.length - 1].x}
            cy={points[points.length - 1].y}
            r="4"
            fill="#ffffff"
            stroke={color}
            strokeWidth="2"
          />
        </svg>
        <div className="chart-latest-badge" style={{ color }}>
          Latest: {latestVal.toFixed(1)}%
        </div>
      </div>
    );
  };

  const cpuData = history.map((s) => s?.cpu?.percent ?? s?.cpu?.cpu_percent ?? 0);
  const memData = history.map((s) => s?.memory?.percent ?? 0);

  const rawProcesses: any[] = telemetry?.top_processes ?? telemetry?.processes?.top_processes_by_cpu ?? [];
  const topProcesses = rawProcesses.slice(0, 7);

  const rawServices: any[] = Array.isArray(telemetry?.services)
    ? telemetry.services
    : (telemetry?.services?.critical_services ?? []);
  const criticalServices = rawServices.slice(0, 8);

  const perCore = telemetry?.cpu?.per_core ?? telemetry?.cpu?.cpu_percent_per_core ?? [];

  return (
    <div className="telemetry-section-grid">
      {/* Telemetry Charts Panel */}
      <div className="panel-card">
        <div className="panel-header">
          <div className="panel-title-group">
            <Activity className="icon-blue" size={18} />
            <h3 className="panel-title">Real-Time Resource Trends</h3>
          </div>
          <span className="panel-subtext">30-Sample Rolling Window</span>
        </div>

        <div className="charts-row">
          <div className="chart-box">
            <div className="chart-title">CPU Utilization (%)</div>
            {renderLineChart(cpuData, '#38bdf8', 'cpuGrad')}
          </div>
          <div className="chart-box">
            <div className="chart-title">RAM Utilization (%)</div>
            {renderLineChart(memData, '#10b981', 'memGrad')}
          </div>
        </div>

        {/* Per-Core Breakdown */}
        {perCore.length > 0 && (
          <div className="per-core-section">
            <div className="per-core-header">Logical Core Distribution ({perCore.length} Cores)</div>
            <div className="cores-grid">
              {perCore.map((coreVal: number, i: number) => (
                <div key={i} className="core-bar-wrapper">
                  <span className="core-label">C{i}</span>
                  <div className="core-bar-bg">
                    <div
                      className={`core-bar-fill ${
                        coreVal > 80 ? 'fill-red' : coreVal > 50 ? 'fill-amber' : 'fill-blue'
                      }`}
                      style={{ height: `${Math.min(coreVal, 100)}%` }}
                    />
                  </div>
                  <span className="core-val">{coreVal.toFixed(0)}%</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Top Processes & Services Column */}
      <div className="side-panels-column">
        {/* Top Processes Table */}
        <div className="panel-card">
          <div className="panel-header">
            <div className="panel-title-group">
              <Server className="icon-purple" size={18} />
              <h3 className="panel-title">Top Active Processes</h3>
            </div>
            <span className="panel-subtext">Sorted by CPU %</span>
          </div>

          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>PID</th>
                  <th>Process Name</th>
                  <th>CPU %</th>
                  <th>RAM (MB)</th>
                  <th>Threads</th>
                </tr>
              </thead>
              <tbody>
                {topProcesses.length > 0 ? (
                  topProcesses.map((proc) => (
                    <tr
                      key={proc.pid}
                      className={proc.cpu_percent > 50 ? 'row-highlight-danger' : ''}
                    >
                      <td className="font-mono text-xs">{proc.pid}</td>
                      <td className="font-semibold text-sm">{proc.name}</td>
                      <td>
                        <span
                          className={`badge ${
                            proc.cpu_percent > 60
                              ? 'badge-critical'
                              : proc.cpu_percent > 20
                              ? 'badge-high'
                              : 'badge-neutral'
                          }`}
                        >
                          {proc.cpu_percent.toFixed(1)}%
                        </span>
                      </td>
                      <td className="text-xs">
                        {proc.memory_mb ? proc.memory_mb.toFixed(0) : (proc.memory_rss_mb ? proc.memory_rss_mb.toFixed(0) : '—')} MB
                      </td>
                      <td className="text-xs">{proc.num_threads ?? proc.status ?? '—'}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={5} className="text-center text-muted py-4">
                      Awaiting process telemetry stream...
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Critical Services Status */}
        <div className="panel-card">
          <div className="panel-header">
            <div className="panel-title-group">
              <AlertCircle className="icon-emerald" size={18} />
              <h3 className="panel-title">Windows Core Services</h3>
            </div>
          </div>

          <div className="services-grid">
            {criticalServices.length > 0 ? (
              criticalServices.map((svc) => (
                <div key={svc.name} className="service-chip">
                  <span
                    className={`status-dot ${
                      svc.status.toLowerCase() === 'running'
                        ? 'dot-green'
                        : 'dot-red'
                    }`}
                  />
                  <div className="service-info">
                    <span className="service-name">{svc.name}</span>
                    <span className="service-status">{svc.status}</span>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-muted text-xs p-2">Monitoring Windows services...</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
