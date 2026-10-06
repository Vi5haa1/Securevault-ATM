import React, { useState, useEffect } from 'react';
import { 
  Search, Filter, Download, ArrowUpDown, ChevronLeft, 
  ChevronRight, RefreshCw, X, ShieldAlert, CheckCircle2,
  Clock, Server, Terminal, AlertTriangle, Layers
} from 'lucide-react';
import { ApiService } from '../services/api';

export const EventExplorer: React.FC = () => {
  const [events, setEvents] = useState<any[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [selectedEventId, setSelectedEventId] = useState<number | null>(null);
  const [eventDetail, setEventDetail] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isExporting, setIsExporting] = useState(false);

  const fetchEvents = async () => {
    setIsLoading(true);
    try {
      const token = ApiService.getToken();
      const params = new URLSearchParams({
        page: String(page),
        page_size: String(pageSize)
      });
      if (search) params.append('search', search);
      if (severityFilter) params.append('severity', severityFilter);

      const res = await fetch(`/api/v1/soc/events?${params.toString()}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setEvents(data.events || []);
        setTotalCount(data.total || 0);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  const fetchEventDetail = async (id: number) => {
    setSelectedEventId(id);
    setEventDetail(null);
    try {
      const token = ApiService.getToken();
      const res = await fetch(`/api/v1/soc/events/${id}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setEventDetail(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleExport = async (format: 'csv' | 'json') => {
    setIsExporting(true);
    try {
      const token = ApiService.getToken();
      const res = await fetch(`/api/v1/soc/events-export?format=${format}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        if (format === 'csv') {
          const blob = await res.blob();
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = 'securevault_siem_events.csv';
          a.click();
        } else {
          const json = await res.json();
          const blob = new Blob([JSON.stringify(json, null, 2)], { type: 'application/json' });
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = 'securevault_siem_events.json';
          a.click();
        }
      }
    } catch (err) {
      alert('Export failed.');
    } finally {
      setIsExporting(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [page, severityFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchEvents();
  };

  const totalPages = Math.ceil(totalCount / pageSize) || 1;

  return (
    <div className="min-h-[calc(100vh-4rem)] p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 glass-panel p-5 rounded-2xl border-slate-800">
        <div>
          <div className="flex items-center space-x-2">
            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30">
              SIEM TELEMETRY
            </span>
            <span className="text-xs text-slate-400 font-mono">10-STAGE DEFENSIVE PIPELINE</span>
          </div>
          <h1 className="text-xl font-bold text-white mt-1">Security Event Explorer</h1>
          <p className="text-xs text-slate-400">Chronological telemetry across ATMs, API Gateway, Auth, and Threat Engines</p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => handleExport('csv')}
            disabled={isExporting}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-xl text-xs font-mono text-slate-300 transition"
          >
            <Download className="w-3.5 h-3.5" />
            <span>EXPORT CSV</span>
          </button>
          <button
            onClick={() => handleExport('json')}
            disabled={isExporting}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-xl text-xs font-mono text-slate-300 transition"
          >
            <Download className="w-3.5 h-3.5" />
            <span>EXPORT JSON</span>
          </button>
          <button
            onClick={fetchEvents}
            className="p-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-xl text-slate-300"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Filters & Search */}
      <div className="flex flex-wrap items-center justify-between gap-4 glass-panel p-4 rounded-2xl border-slate-800">
        <form onSubmit={handleSearchSubmit} className="flex-1 min-w-[280px] max-w-md relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
          <input
            type="text"
            placeholder="Search event type, source, IP, correlation key..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
        </form>

        <div className="flex items-center space-x-2 text-xs font-mono">
          <span className="text-slate-400">Severity:</span>
          {(['', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const).map(sev => (
            <button
              key={sev}
              onClick={() => { setSeverityFilter(sev); setPage(1); }}
              className={`px-2.5 py-1 rounded-lg transition ${
                severityFilter === sev
                  ? 'bg-blue-600 text-white font-bold'
                  : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
              }`}
            >
              {sev || 'ALL'}
            </button>
          ))}
        </div>
      </div>

      {/* Events Table */}
      <div className="glass-panel rounded-2xl border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/80 text-slate-400 font-mono text-[11px] border-b border-slate-800 uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Event ID</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Source / Origin</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Detection Rule</th>
                <th className="py-3 px-4">MITRE Technique</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-900 font-mono">
              {events.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-500 font-sans">
                    No security events found matching the criteria.
                  </td>
                </tr>
              ) : (
                events.map(ev => {
                  const isCritical = ev.severity === 'CRITICAL';
                  const isHigh = ev.severity === 'HIGH';
                  return (
                    <tr 
                      key={ev.id}
                      onClick={() => fetchEventDetail(ev.id)}
                      className="hover:bg-slate-900/50 cursor-pointer transition group"
                    >
                      <td className="py-3 px-4 font-bold text-blue-400">{ev.event_id}</td>
                      <td className="py-3 px-4 text-slate-400 text-[11px]">
                        {ev.created_at ? new Date(ev.created_at).toLocaleTimeString() : 'N/A'}
                      </td>
                      <td className="py-3 px-4">
                        <span className="text-white font-semibold">{ev.type}</span>
                        {ev.is_simulated && (
                          <span className="ml-1.5 px-1 py-0.2 rounded bg-purple-500/20 text-purple-400 text-[9px] border border-purple-500/30">
                            SIM
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          isCritical ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                          isHigh ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                          ev.severity === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                          'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        }`}>
                          {ev.severity}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-300">{ev.source}</td>
                      <td className="py-3 px-4">
                        <span className={`font-bold ${ev.risk_score > 60 ? 'text-rose-400' : 'text-slate-300'}`}>
                          {ev.risk_score}/100
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-300 max-w-[180px] truncate">
                        {ev.fired_rule || 'N/A'}
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px]">
                        {ev.mitre_technique || 'N/A'}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <span className="text-blue-400 group-hover:text-cyan-300 text-[11px] font-sans">
                          Inspect &rarr;
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="p-4 border-t border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400">
          <span>Showing {events.length} of {totalCount} events</span>
          <div className="flex items-center space-x-2">
            <button
              disabled={page <= 1}
              onClick={() => setPage(p => Math.max(1, p - 1))}
              className="p-1 rounded bg-slate-900 border border-slate-800 disabled:opacity-40"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span>Page {page} of {totalPages}</span>
            <button
              disabled={page >= totalPages}
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              className="p-1 rounded bg-slate-900 border border-slate-800 disabled:opacity-40"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Event Detail Drawer with Pipeline Trace */}
      {selectedEventId && (
        <div className="fixed inset-y-0 right-0 z-50 w-full max-w-xl bg-slate-950/95 backdrop-blur-xl border-l border-slate-800 shadow-2xl flex flex-col animate-in slide-in-from-right duration-200">
          <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
            <div>
              <span className="font-mono text-xs text-blue-400 font-bold">
                {eventDetail?.event_id || `EVT-${selectedEventId}`}
              </span>
              <h2 className="text-base font-bold text-white mt-0.5">{eventDetail?.type}</h2>
            </div>
            <button 
              onClick={() => setSelectedEventId(null)}
              className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto p-5 space-y-6">
            {!eventDetail ? (
              <div className="flex items-center justify-center h-48">
                <RefreshCw className="w-6 h-6 text-blue-400 animate-spin" />
              </div>
            ) : (
              <>
                {/* Meta Overview */}
                <div className="glass-panel p-4 rounded-2xl border-slate-800 space-y-2 text-xs font-mono">
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-400">Severity:</span>
                    <span className="text-rose-400 font-bold">{eventDetail.severity}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-400">Source:</span>
                    <span className="text-slate-200">{eventDetail.source}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-400">Correlation Key:</span>
                    <span className="text-cyan-400">{eventDetail.correlation_key}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-900">
                    <span className="text-slate-400">MITRE Technique:</span>
                    <span className="text-purple-400">{eventDetail.mitre_technique} [{eventDetail.mitre_tactic}]</span>
                  </div>
                  {eventDetail.incident && (
                    <div className="flex justify-between py-1 border-b border-slate-900">
                      <span className="text-slate-400">Correlated Incident:</span>
                      <span className="text-amber-400 font-bold">{eventDetail.incident.incident_code}</span>
                    </div>
                  )}
                </div>

                {/* Visible 10-Stage Pipeline Trace */}
                <div className="space-y-3">
                  <div className="flex items-center space-x-2 text-blue-400">
                    <Layers className="w-4 h-4" />
                    <h3 className="text-xs font-bold text-white uppercase font-mono tracking-wider">
                      Event Pipeline Trace
                    </h3>
                  </div>

                  <div className="space-y-2">
                    {(eventDetail.pipeline_trace || []).map((step: any, idx: number) => (
                      <div 
                        key={idx}
                        className="p-3 bg-slate-900/70 border border-slate-800 rounded-xl space-y-1 text-xs font-mono"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-cyan-400">{step.stage}</span>
                          <span className="text-[10px] text-slate-500">{step.duration_ms} ms</span>
                        </div>
                        <p className="text-slate-300 text-[11px] font-sans">{step.result}</p>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Raw Normalized Payload */}
                <div className="space-y-2">
                  <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block">Raw Payload</span>
                  <pre className="p-3 bg-slate-950 rounded-xl border border-slate-800 text-[11px] text-emerald-400 font-mono overflow-x-auto">
                    {JSON.stringify(eventDetail.details, null, 2)}
                  </pre>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
