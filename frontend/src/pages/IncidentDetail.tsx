import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ShieldAlert, AlertTriangle, Clock, CheckCircle2, FileText, Download,
  Send, Lock, Unlock, Server, Activity, ChevronRight, RefreshCw, Eye
} from 'lucide-react';
import { ApiService } from '../services/api';

interface IncidentAction {
  id: number;
  action_type: string;
  result: string;
  created_at: string;
}

interface IncidentNote {
  id: number;
  author_id: number;
  author_name?: string;
  text: string;
  created_at: string;
}

interface IncidentEvent {
  id: number;
  type: string;
  severity: string;
  source: string;
  ip_address?: string;
  created_at: string;
  details: any;
  mitre_technique?: string;
  mitre_tactic?: string;
  rule_id?: string;
}

interface IncidentItem {
  id: number;
  incident_code: string;
  severity: string;
  threat_type: string;
  atm_id?: number;
  account_id?: number;
  status: string;
  assigned_analyst_id?: number;
  summary: string;
  created_at: string;
  resolved_at?: string;
  is_simulated: boolean;
  actions: IncidentAction[];
  notes: IncidentNote[];
  events?: IncidentEvent[];
  atm_details?: any;
}

export const IncidentDetail: React.FC = () => {
  const { id } = useParams<{ id?: string }>();
  const navigate = useNavigate();

  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<IncidentItem | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'TIMELINE' | 'EVIDENCE' | 'PLAYBOOK' | 'NOTES'>('TIMELINE');
  const [newNote, setNewNote] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [actionLoading, setActionLoading] = useState(false);
  const [statusModalOpen, setStatusModalOpen] = useState(false);
  const [newStatus, setNewStatus] = useState<string>('INVESTIGATING');
  const [statusReason, setStatusReason] = useState<string>('');

  const loadIncidents = async () => {
    setLoading(true);
    try {
      const data = await ApiService.getIncidents();
      setIncidents(data);
      if (id) {
        const found = data.find((x: any) => x.id === parseInt(id));
        if (found) {
          loadSingleIncident(found.id);
        }
      } else if (data.length > 0 && !selectedIncident) {
        loadSingleIncident(data[0].id);
      }
    } catch (err) {
      console.error('Failed to load incidents:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadSingleIncident = async (incidentId: number) => {
    try {
      const data = await ApiService.getIncident(incidentId);
      setSelectedIncident(data);
    } catch (err) {
      console.error('Failed to load single incident:', err);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, [id]);

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncident || !newNote.trim()) return;
    try {
      await ApiService.addIncidentNote(selectedIncident.id, newNote);
      setNewNote('');
      loadSingleIncident(selectedIncident.id);
    } catch (err) {
      console.error('Failed to add note:', err);
    }
  };

  const handleUpdateStatus = async () => {
    if (!selectedIncident) return;
    setActionLoading(true);
    try {
      await ApiService.updateIncidentStatus(selectedIncident.id, newStatus, statusReason);
      setStatusModalOpen(false);
      setStatusReason('');
      await loadSingleIncident(selectedIncident.id);
      loadIncidents();
    } catch (err) {
      console.error('Failed to update status:', err);
    } finally {
      setActionLoading(false);
    }
  };

  const handleExportReport = async () => {
    if (!selectedIncident) return;
    try {
      const res = await ApiService.exportIncident(selectedIncident.id);
      const blob = new Blob([JSON.stringify(res, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${selectedIncident.incident_code}-FORENSIC-REPORT.json`;
      a.click();
    } catch (err) {
      console.error('Export failed:', err);
    }
  };

  const filteredIncidents = incidents.filter(item => {
    if (statusFilter === 'ALL') return true;
    return item.status === statusFilter;
  });

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-rose-500" />
            Security Incident Investigation Console
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            End-to-end incident management, chronological timeline, automated playbook traces, and cryptographically verified evidence.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={loadIncidents}
            disabled={loading}
            className="flex items-center space-x-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs transition border border-slate-700 font-medium"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-rose-400' : ''}`} />
            <span>Refresh</span>
          </button>
          {selectedIncident && (
            <button
              onClick={handleExportReport}
              className="flex items-center space-x-2 px-3 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs transition font-medium shadow-md shadow-blue-600/30"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Forensic Report</span>
            </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Incident List */}
        <div className="lg:col-span-4 space-y-3">
          <div className="flex items-center justify-between bg-slate-900/60 p-3 rounded-xl border border-slate-800">
            <span className="text-xs font-mono text-slate-400 uppercase font-bold">Incidents ({filteredIncidents.length})</span>
            <select
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded px-2 py-1 font-mono focus:outline-none"
            >
              <option value="ALL">All Statuses</option>
              <option value="OPEN">Open</option>
              <option value="INVESTIGATING">Investigating</option>
              <option value="CONTAINED">Contained</option>
              <option value="RESOLVED">Resolved</option>
            </select>
          </div>

          <div className="space-y-2 max-h-[750px] overflow-y-auto pr-1">
            {filteredIncidents.map(inc => {
              const isSelected = selectedIncident?.id === inc.id;
              return (
                <div
                  key={inc.id}
                  onClick={() => loadSingleIncident(inc.id)}
                  className={`p-3.5 rounded-xl border cursor-pointer transition ${
                    isSelected
                      ? 'bg-rose-950/20 border-rose-500/50 shadow-md shadow-rose-950/30'
                      : 'bg-slate-900/40 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-white">
                      {inc.incident_code}
                    </span>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-semibold ${
                      inc.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                      inc.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                      'bg-blue-500/20 text-blue-400'
                    }`}>
                      {inc.severity}
                    </span>
                  </div>
                  <div className="text-xs font-medium text-slate-200 mt-1.5 line-clamp-1">
                    {inc.threat_type}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1 line-clamp-2">
                    {inc.summary}
                  </div>
                  <div className="flex items-center justify-between mt-3 text-[10px] font-mono text-slate-500 pt-2 border-t border-slate-800/60">
                    <span className={`px-1.5 py-0.5 rounded ${
                      inc.status === 'OPEN' ? 'text-rose-400 bg-rose-500/10' :
                      inc.status === 'INVESTIGATING' ? 'text-amber-400 bg-amber-500/10' :
                      inc.status === 'CONTAINED' ? 'text-purple-400 bg-purple-500/10' :
                      'text-emerald-400 bg-emerald-500/10'
                    }`}>
                      {inc.status}
                    </span>
                    <span>{new Date(inc.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                  </div>
                </div>
              );
            })}
            {filteredIncidents.length === 0 && (
              <div className="text-center py-12 text-slate-500 text-xs font-mono border border-dashed border-slate-800 rounded-xl">
                No incidents found for this filter.
              </div>
            )}
          </div>
        </div>

        {/* Right: Selected Incident Detail */}
        <div className="lg:col-span-8 space-y-4">
          {selectedIncident ? (
            <>
              {/* Incident Header Card */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-4">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="font-mono text-lg font-extrabold text-white">
                        {selectedIncident.incident_code}
                      </span>
                      {selectedIncident.is_simulated && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                          SIMULATED
                        </span>
                      )}
                    </div>
                    <div className="text-sm font-semibold text-rose-400 mt-1">
                      {selectedIncident.threat_type}
                    </div>
                  </div>

                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => {
                        setNewStatus(selectedIncident.status);
                        setStatusModalOpen(true);
                      }}
                      className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono font-medium border border-slate-700 transition"
                    >
                      Update Status ({selectedIncident.status})
                    </button>
                  </div>
                </div>

                {/* Metadata Grid */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                  <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800/60 font-mono">
                    <span className="text-slate-500 text-[10px] block">SEVERITY</span>
                    <span className="font-bold text-rose-400">{selectedIncident.severity}</span>
                  </div>
                  <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800/60 font-mono">
                    <span className="text-slate-500 text-[10px] block">ATM TERMINAL</span>
                    <span className="font-bold text-slate-200">
                      {selectedIncident.atm_details?.atm_code || (selectedIncident.atm_id ? `ID #${selectedIncident.atm_id}` : 'N/A')}
                    </span>
                  </div>
                  <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800/60 font-mono">
                    <span className="text-slate-500 text-[10px] block">STATUS</span>
                    <span className="font-bold text-emerald-400">{selectedIncident.status}</span>
                  </div>
                  <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800/60 font-mono">
                    <span className="text-slate-500 text-[10px] block">DETECTED AT</span>
                    <span className="text-slate-300">
                      {new Date(selectedIncident.created_at).toLocaleString()}
                    </span>
                  </div>
                </div>

                <div className="text-xs text-slate-300 bg-slate-950/70 p-3 rounded-lg border border-slate-800/50">
                  <span className="text-slate-400 font-mono text-[11px] block mb-1">INCIDENT SUMMARY</span>
                  {selectedIncident.summary}
                </div>
              </div>

              {/* Tabs Navigation */}
              <div className="flex border-b border-slate-800 space-x-1">
                {(['TIMELINE', 'EVIDENCE', 'PLAYBOOK', 'NOTES'] as const).map(tab => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`px-4 py-2 text-xs font-mono font-medium transition border-b-2 ${
                      activeTab === tab
                        ? 'border-rose-500 text-rose-400 bg-slate-900/40'
                        : 'border-transparent text-slate-400 hover:text-slate-300'
                    }`}
                  >
                    {tab}
                  </button>
                ))}
              </div>

              {/* Tab Contents */}
              <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-5 min-h-[350px]">
                {/* 1. TIMELINE */}
                {activeTab === 'TIMELINE' && (
                  <div className="space-y-4">
                    <div className="text-xs font-mono text-slate-400 mb-2">CHRONOLOGICAL PIPELINE AUDIT TIMELINE</div>
                    <div className="relative border-l border-slate-800 ml-3 space-y-6">
                      {/* Fired events */}
                      {selectedIncident.events && selectedIncident.events.map((ev, idx) => (
                        <div key={ev.id} className="relative pl-6">
                          <span className="absolute -left-1.5 top-1.5 w-3 h-3 rounded-full bg-rose-500 border-2 border-slate-950 shadow-[0_0_8px_#f43f5e]" />
                          <div className="text-xs font-mono text-slate-400">
                            {new Date(ev.created_at).toLocaleTimeString()} · Stage: Pipeline Correlated
                          </div>
                          <div className="text-sm font-bold text-white mt-0.5">
                            {ev.type}
                          </div>
                          <div className="text-xs text-slate-400 mt-1">
                            Source: <span className="font-mono text-cyan-400">{ev.source}</span>
                            {ev.mitre_technique && (
                              <span className="ml-2 font-mono text-indigo-400">
                                MITRE: {ev.mitre_technique}
                              </span>
                            )}
                          </div>
                        </div>
                      ))}

                      {/* Playbook execution actions */}
                      {selectedIncident.actions.map(act => (
                        <div key={act.id} className="relative pl-6">
                          <span className="absolute -left-1.5 top-1.5 w-3 h-3 rounded-full bg-emerald-400 border-2 border-slate-950 shadow-[0_0_8px_#34d399]" />
                          <div className="text-xs font-mono text-slate-400">
                            {new Date(act.created_at).toLocaleTimeString()} · Automated Playbook Step
                          </div>
                          <div className="text-sm font-bold text-emerald-300 mt-0.5">
                            {act.action_type}
                          </div>
                          <div className="text-xs text-slate-300 font-mono mt-0.5">
                            Result: {act.result}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* 2. EVIDENCE */}
                {activeTab === 'EVIDENCE' && (
                  <div className="space-y-4">
                    {/* ATM Telemetry Snapshot */}
                    {selectedIncident.atm_details && (
                      <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-xs font-bold text-slate-300 flex items-center gap-2">
                            <Server className="w-4 h-4 text-cyan-400" />
                            ATM Telemetry Snapshot at Incident Time
                          </span>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400">
                            IMMUTABLE SNAPSHOT
                          </span>
                        </div>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
                          <div>
                            <span className="text-slate-500 block text-[10px]">CPU USAGE</span>
                            <span className="text-white">{selectedIncident.atm_details.cpu_usage || 24}%</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block text-[10px]">LATENCY</span>
                            <span className="text-white">{selectedIncident.atm_details.network_latency_ms || 18}ms</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block text-[10px]">CASH LEVEL</span>
                            <span className="text-white">{selectedIncident.atm_details.cash_level_percentage || 85}%</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block text-[10px]">CERTIFICATE</span>
                            <span className="text-emerald-400">{selectedIncident.atm_details.certificate_status || 'VALID'}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block text-[10px]">FIRMWARE</span>
                            <span className="text-cyan-400">{selectedIncident.atm_details.firmware_version || 'SV-ATM-FW-3.4.1'}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block text-[10px]">LOCKDOWN STATE</span>
                            <span className={selectedIncident.atm_details.is_locked_down ? 'text-rose-400 font-bold' : 'text-slate-400'}>
                              {selectedIncident.atm_details.is_locked_down ? 'LOCKED DOWN' : 'NORMAL'}
                            </span>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Linked Security Events */}
                    <div className="space-y-2">
                      <div className="text-xs font-mono text-slate-400">LINKED CORRELATED EVENTS</div>
                      {selectedIncident.events && selectedIncident.events.map(e => (
                        <div key={e.id} className="bg-slate-950 p-3 rounded-lg border border-slate-800/80 space-y-1">
                          <div className="flex items-center justify-between text-xs">
                            <span className="font-mono font-bold text-white">{e.type}</span>
                            <span className="text-[10px] font-mono text-slate-400">{new Date(e.created_at).toLocaleString()}</span>
                          </div>
                          <pre className="text-[11px] font-mono text-slate-400 bg-slate-900 p-2 rounded overflow-x-auto">
                            {JSON.stringify(e.details, null, 2)}
                          </pre>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* 3. PLAYBOOK */}
                {activeTab === 'PLAYBOOK' && (
                  <div className="space-y-3">
                    <div className="text-xs font-mono text-slate-400 mb-2">AUTOMATED SOAR PLAYBOOK EXECUTION TRACE</div>
                    {selectedIncident.actions.map((act, index) => (
                      <div key={act.id} className="bg-slate-950 p-3 rounded-xl border border-slate-800 flex items-start gap-3">
                        <div className="w-6 h-6 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-xs font-bold shrink-0">
                          {index + 1}
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-xs font-bold text-emerald-400">
                              {act.action_type}
                            </span>
                            <span className="text-[10px] font-mono text-slate-500">
                              {new Date(act.created_at).toLocaleTimeString()}
                            </span>
                          </div>
                          <p className="text-xs text-slate-300 mt-1 font-mono">
                            {act.result}
                          </p>
                        </div>
                      </div>
                    ))}
                    {selectedIncident.actions.length === 0 && (
                      <div className="text-center py-8 text-xs text-slate-500 font-mono">
                        No automated playbook actions recorded for this incident.
                      </div>
                    )}
                  </div>
                )}

                {/* 4. NOTES */}
                {activeTab === 'NOTES' && (
                  <div className="space-y-4">
                    <div className="text-xs font-mono text-slate-400 mb-2">ANALYST INVESTIGATION NOTES</div>
                    <div className="space-y-2">
                      {selectedIncident.notes.map(n => (
                        <div key={n.id} className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                          <div className="flex items-center justify-between text-[11px] font-mono text-slate-500">
                            <span className="text-slate-300 font-bold">{n.author_name || 'SOC Analyst'}</span>
                            <span>{new Date(n.created_at).toLocaleString()}</span>
                          </div>
                          <p className="text-xs text-slate-300 mt-1 whitespace-pre-wrap">{n.text}</p>
                        </div>
                      ))}
                      {selectedIncident.notes.length === 0 && (
                        <div className="text-center py-6 text-xs text-slate-500 font-mono">
                          No analyst notes added yet.
                        </div>
                      )}
                    </div>

                    <form onSubmit={handleAddNote} className="space-y-2 pt-2 border-t border-slate-800">
                      <textarea
                        value={newNote}
                        onChange={e => setNewNote(e.target.value)}
                        placeholder="Add investigative findings, forensic analysis notes, or containment rationale..."
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-rose-500"
                        rows={3}
                      />
                      <div className="flex justify-end">
                        <button
                          type="submit"
                          disabled={!newNote.trim()}
                          className="flex items-center space-x-1.5 px-3 py-1.5 bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white rounded-lg text-xs font-medium transition"
                        >
                          <Send className="w-3 h-3" />
                          <span>Add Note</span>
                        </button>
                      </div>
                    </form>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-12 text-center text-slate-500 font-mono text-sm">
              Select an incident from the list to investigate.
            </div>
          )}
        </div>
      </div>

      {/* Status Update Modal */}
      {statusModalOpen && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-4">
            <h3 className="text-lg font-bold text-white">Update Incident Status</h3>
            <div className="space-y-3">
              <div>
                <label className="text-xs font-mono text-slate-400 block mb-1">New Status</label>
                <select
                  value={newStatus}
                  onChange={e => setNewStatus(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none"
                >
                  <option value="OPEN">OPEN</option>
                  <option value="INVESTIGATING">INVESTIGATING</option>
                  <option value="CONTAINED">CONTAINED</option>
                  <option value="RESOLVED">RESOLVED</option>
                </select>
              </div>
              <div>
                <label className="text-xs font-mono text-slate-400 block mb-1">Audited Rationale / Resolution Note</label>
                <textarea
                  value={statusReason}
                  onChange={e => setStatusReason(e.target.value)}
                  placeholder="Document reason for status change (mandatory for compliance audit)..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none"
                  rows={3}
                />
              </div>
            </div>
            <div className="flex justify-end space-x-2 pt-2">
              <button
                onClick={() => setStatusModalOpen(false)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleUpdateStatus}
                disabled={actionLoading}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-semibold transition"
              >
                {actionLoading ? 'Updating...' : 'Save & Audit'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
