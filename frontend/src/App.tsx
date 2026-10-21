import React, { useState, useEffect, useCallback } from 'react';
import { Navbar } from './components/Navbar';
import { StatsCards } from './components/StatsCards';
import { TelemetryCharts } from './components/TelemetryCharts';
import { IncidentList } from './components/IncidentList';
import { IncidentDetailModal } from './components/IncidentDetailModal';
import { SimulatorPanel } from './components/SimulatorPanel';
import { KnowledgeSearch } from './components/KnowledgeSearch';
import { useWebSocket } from './hooks/useWebSocket';
import {
  getIncidents,
  getIncidentStats,
  getIncidentById,
  triggerInvestigation,
  updateIncidentStatus,
  executeIncidentAction,
  collectTelemetryNow,
  getLatestTelemetry,
} from './services/api';
import type { Incident, StatsSummary, TelemetrySnapshot } from './types';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'incidents' | 'knowledge' | 'simulator'>('dashboard');
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [stats, setStats] = useState<StatsSummary | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isLoadingIncidents, setIsLoadingIncidents] = useState(false);
  const [isRefreshingTelemetry, setIsRefreshingTelemetry] = useState(false);
  const [telemetry, setTelemetry] = useState<TelemetrySnapshot | null>(null);

  const { connectionState, latestTelemetry: wsTelemetry, telemetryHistory, lastEvent } = useWebSocket();

  // Keep telemetry state synced with WebSocket live stream
  useEffect(() => {
    if (wsTelemetry) {
      setTelemetry(wsTelemetry);
    }
  }, [wsTelemetry]);

  // Initial fetch of telemetry on page load
  useEffect(() => {
    getLatestTelemetry().then(setTelemetry).catch(console.error);
  }, []);

  // Load incidents & stats
  const fetchIncidentsData = useCallback(async () => {
    try {
      setIsLoadingIncidents(true);
      const [incRes, statsRes] = await Promise.all([
        getIncidents({ limit: 50 }),
        getIncidentStats(),
      ]);
      setIncidents(incRes.incidents);
      setStats(statsRes);
    } catch (err) {
      console.error('Failed to fetch incidents or stats:', err);
    } finally {
      setIsLoadingIncidents(false);
    }
  }, []);

  useEffect(() => {
    fetchIncidentsData();
    // Poll stats & incidents every 10 seconds as a fallback
    const interval = setInterval(fetchIncidentsData, 10000);
    return () => clearInterval(interval);
  }, [fetchIncidentsData]);

  // Reactive updates on WebSocket events
  useEffect(() => {
    if (!lastEvent) return;
    const triggerEvents = [
      'incident_detected',
      'investigation_started',
      'investigation_completed',
      'status_changed',
      'action_executed',
    ];
    if (triggerEvents.includes(lastEvent.type)) {
      fetchIncidentsData();
      // If modal is open for this incident, refresh its details
      if (selectedIncident && lastEvent.data?.incident_id === selectedIncident.id) {
        getIncidentById(selectedIncident.id).then(setSelectedIncident).catch(console.error);
      }
    }
  }, [lastEvent, fetchIncidentsData, selectedIncident]);

  // Select incident & open modal
  const handleSelectIncident = async (id: string) => {
    try {
      const inc = await getIncidentById(id);
      setSelectedIncident(inc);
      setIsModalOpen(true);
    } catch (err) {
      console.error('Failed to load incident detail:', err);
    }
  };

  // Trigger investigation
  const handleInvestigate = async (id: string) => {
    try {
      await triggerInvestigation(id);
      await fetchIncidentsData();
      if (selectedIncident && selectedIncident.id === id) {
        const updated = await getIncidentById(id);
        setSelectedIncident(updated);
      }
    } catch (err) {
      console.error('Failed to trigger investigation:', err);
      alert(`Investigation failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  // Action approval / rejection
  const handleApproveAction = async (actionId: string) => {
    try {
      await executeIncidentAction(actionId, true);
    } catch (err) {
      console.error('Failed to approve action:', err);
    } finally {
      if (selectedIncident) {
        const updated = await getIncidentById(selectedIncident.id);
        setSelectedIncident(updated);
      }
      await fetchIncidentsData();
    }
  };

  const handleRejectAction = async (actionId: string) => {
    try {
      await executeIncidentAction(actionId, false);
    } catch (err) {
      console.error('Failed to reject action:', err);
    } finally {
      if (selectedIncident) {
        const updated = await getIncidentById(selectedIncident.id);
        setSelectedIncident(updated);
      }
      await fetchIncidentsData();
    }
  };

  // Resolve incident
  const handleResolve = async (id: string) => {
    try {
      await updateIncidentStatus(id, 'resolved', 'Resolved by operator from dashboard');
      await fetchIncidentsData();
      if (selectedIncident && selectedIncident.id === id) {
        const updated = await getIncidentById(id);
        setSelectedIncident(updated);
      }
    } catch (err) {
      console.error('Failed to resolve incident:', err);
      alert(`Resolve failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  // Manual telemetry refresh
  const handleRefreshTelemetry = async () => {
    try {
      setIsRefreshingTelemetry(true);
      const snap = await collectTelemetryNow();
      setTelemetry(snap);
    } catch (err) {
      console.error('Manual telemetry collection failed:', err);
    } finally {
      setIsRefreshingTelemetry(false);
    }
  };

  return (
    <div className="app-container">
      {/* Top Navbar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={(tab) => setActiveTab(tab as typeof activeTab)}
        connectionState={connectionState}
        latestTelemetry={telemetry}
        onRefreshTelemetry={handleRefreshTelemetry}
        isRefreshing={isRefreshingTelemetry}
      />

      {/* Main Content Area */}
      <main className="main-content">
        {activeTab === 'dashboard' && (
          <div className="tab-pane">
            <StatsCards telemetry={telemetry} stats={stats} />
            <TelemetryCharts
              telemetry={telemetry}
              history={telemetryHistory}
            />

            {/* Quick Incidents Glance */}
            <div className="section-card mt-6">
              <div className="section-header">
                <div>
                  <h3 className="section-heading">Active Incidents Queue</h3>
                  <p className="section-subheading">
                    Latest anomalies detected by Autoencoder requiring investigation or remediation
                  </p>
                </div>
                <button
                  className="btn btn-outline btn-sm"
                  onClick={() => setActiveTab('incidents')}
                >
                  View Full Queue ({incidents.length})
                </button>
              </div>

              <IncidentList
                incidents={incidents.slice(0, 5)}
                selectedIncidentId={selectedIncident?.id ?? null}
                onSelectIncident={handleSelectIncident}
                onInvestigate={handleInvestigate}
                onResolve={handleResolve}
                isLoading={isLoadingIncidents}
              />
            </div>
          </div>
        )}

        {activeTab === 'incidents' && (
          <div className="tab-pane">
            <StatsCards telemetry={telemetry} stats={stats} />
            <div className="section-card mt-6">
              <div className="section-header">
                <div>
                  <h2 className="section-heading">Incident Management Console</h2>
                  <p className="section-subheading">
                    Full triage queue with automated state transitions, forensic telemetry, and AI agent reports
                  </p>
                </div>
              </div>

              <IncidentList
                incidents={incidents}
                selectedIncidentId={selectedIncident?.id ?? null}
                onSelectIncident={handleSelectIncident}
                onInvestigate={handleInvestigate}
                onResolve={handleResolve}
                isLoading={isLoadingIncidents}
              />
            </div>
          </div>
        )}

        {activeTab === 'knowledge' && (
          <div className="tab-pane">
            <KnowledgeSearch />
          </div>
        )}

        {activeTab === 'simulator' && (
          <div className="tab-pane">
            <SimulatorPanel />
          </div>
        )}
      </main>

      {/* Incident Detail Modal */}
      <IncidentDetailModal
        incident={selectedIncident}
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onInvestigate={handleInvestigate}
        onApproveAction={handleApproveAction}
        onRejectAction={handleRejectAction}
        onResolve={handleResolve}
      />
    </div>
  );
};

export default App;
