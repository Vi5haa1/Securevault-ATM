import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, Activity, 
  MapPin, RefreshCw, X, CheckCircle2, AlertOctagon, 
  Server, Lock, Unlock, Eye, Database, Bug, Radio
} from 'lucide-react';
import { MapContainer, Marker, Popup } from 'react-leaflet';
import L from 'leaflet';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, PieChart, Pie, Cell } from 'recharts';
import { ApiService } from '../services/api';
import { Atm, Incident, Alert, AuditVerify } from '../types';
import { MapTileProvider } from '../components/MapProvider';
import { AtmSecurityDrawer } from '../components/AtmSecurityDrawer';
import { useRealtimeWs } from '../services/websocket';

// Dynamic Leaflet marker icons with live threat pulse
const createCustomMarker = (atm: any) => {
  const isAttack = atm.under_attack || atm.status === 'LOCKDOWN';
  let color = atm.marker_color || (
    atm.status === 'ONLINE' ? '#10b981' :
    atm.status === 'LOCKDOWN' ? '#ef4444' :
    atm.status === 'OFFLINE' ? '#64748b' :
    atm.status === 'MAINTENANCE' ? '#f59e0b' : '#f97316'
  );
  if (isAttack) color = '#ef4444';

  const pulseHtml = isAttack
    ? `<div style="position: absolute; top: -6px; left: -6px; width: 28px; height: 28px; border-radius: 50%; background-color: rgba(239, 68, 68, 0.45); animation: ping 1.2s cubic-bezier(0, 0, 0.2, 1) infinite;"></div>`
    : '';

  return L.divIcon({
    className: 'custom-leaflet-pin',
    html: `<div style="position: relative; width: 16px; height: 16px;">
      ${pulseHtml}
      <div style="background-color: ${color}; width: 16px; height: 16px; border-radius: 50%; border: 2.5px solid white; box-shadow: 0 0 12px ${color}; position: relative; z-index: 10;"></div>
    </div>`,
    iconSize: [16, 16],
    iconAnchor: [8, 8]
  });
};

const SEVERITY_COLORS: Record<string, string> = {
  LOW: '#10b981',
  MEDIUM: '#f59e0b',
  HIGH: '#f97316',
  CRITICAL: '#ef4444'
};

export const SocDashboard: React.FC = () => {
  // Staff login state
  const [isStaffLoggedIn, setIsStaffLoggedIn] = useState(false);
  const [username, setUsername] = useState('analyst1');
  const [password, setPassword] = useState('Analyst@1234');
  const [loginError, setLoginError] = useState<string | null>(null);

  // KPIs & Data
  const [kpis, setKpis] = useState<any>(null);
  const [atms, setAtms] = useState<Atm[]>([]);
  const [selectedAtm, setSelectedAtm] = useState<Atm | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [analytics, setAnalytics] = useState<any>(null);
  const [auditInfo, setAuditInfo] = useState<AuditVerify | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [mapFilter, setMapFilter] = useState<'ALL' | 'ONLINE' | 'OFFLINE' | 'MAINTENANCE' | 'ATTACK' | 'HIGH_RISK' | 'LOCKDOWN'>('ALL');

  const filterCounts = {
    ALL: atms.length,
    ONLINE: atms.filter(a => a.status === 'ONLINE').length,
    OFFLINE: atms.filter(a => a.status === 'OFFLINE').length,
    MAINTENANCE: atms.filter(a => a.status === 'MAINTENANCE').length,
    ATTACK: atms.filter(a => (a as any).under_attack || a.status === 'LOCKDOWN').length,
    HIGH_RISK: atms.filter(a => ((a as any).risk_score || 0) > 60).length,
    LOCKDOWN: atms.filter(a => a.status === 'LOCKDOWN').length,
  };

  const filteredAtms = atms.filter(a => {
    if (mapFilter === 'ONLINE') return a.status === 'ONLINE';
    if (mapFilter === 'OFFLINE') return a.status === 'OFFLINE';
    if (mapFilter === 'MAINTENANCE') return a.status === 'MAINTENANCE';
    if (mapFilter === 'ATTACK') return (a as any).under_attack || a.status === 'LOCKDOWN';
    if (mapFilter === 'HIGH_RISK') return ((a as any).risk_score || 0) > 60;
    if (mapFilter === 'LOCKDOWN') return a.status === 'LOCKDOWN';
    return true;
  });

  // Tamper Demo
  const [tamperMsg, setTamperMsg] = useState<string | null>(null);
  const [tamperedLogId, setTamperedLogId] = useState<number | null>(null);

  // Check login
  useEffect(() => {
    ApiService.ensureAdminAuth().then((authed) => {
      if (authed) {
        setIsStaffLoggedIn(true);
      } else {
        const u = ApiService.getCurrentUser();
        if (u && u.role !== 'CUSTOMER') {
          setIsStaffLoggedIn(true);
        }
      }
    });
  }, []);

  const handleStaffLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError(null);
    try {
      const res = await ApiService.loginStaff(username, password);
      ApiService.setAuth(res.access_token, { username: res.username, role: res.role });
      setIsStaffLoggedIn(true);
      loadDashboardData();
    } catch (err: any) {
      setLoginError(err.message || 'Staff login failed.');
    }
  };

  const loadDashboardData = async () => {
    setIsLoading(true);
    try {
      const [kpiRes, mapRes, incRes, alertRes, analRes, auditRes] = await Promise.all([
        ApiService.getSocKpis().catch(() => null),
        ApiService.getSocMap().catch(() => []),
        ApiService.getIncidents().catch(() => []),
        ApiService.getAlerts().catch(() => []),
        ApiService.getSocAnalytics().catch(() => null),
        ApiService.verifyAudit().catch(() => null),
      ]);

      if (kpiRes) setKpis(kpiRes);
      if (mapRes) setAtms(mapRes);
      if (incRes) setIncidents(incRes);
      if (alertRes) setAlerts(alertRes);
      if (analRes) setAnalytics(analRes);
      if (auditRes) setAuditInfo(auditRes);
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  const { isConnected, lastTelemetry, lastAlert } = useRealtimeWs();

  // Ingest live WebSocket telemetry updates smoothly without full page reload
  useEffect(() => {
    if (lastTelemetry && lastTelemetry.length > 0) {
      setAtms(prevAtms => {
        if (!prevAtms || prevAtms.length === 0) return lastTelemetry;
        return prevAtms.map(existing => {
          const update = lastTelemetry.find((t: any) => t.id === existing.id);
          return update ? { ...existing, ...update } : existing;
        });
      });

      if (selectedAtm) {
        const update = lastTelemetry.find((t: any) => t.id === selectedAtm.id);
        if (update) {
          setSelectedAtm(prev => prev ? { ...prev, ...update } : null);
        }
      }
    }
  }, [lastTelemetry]);

  // Ingest live WebSocket security alerts
  useEffect(() => {
    if (lastAlert) {
      setAlerts(prev => {
        if (prev.some(a => a.id === lastAlert.alert_id)) return prev;
        const newAlert: any = {
          id: lastAlert.alert_id,
          title: lastAlert.title,
          message: lastAlert.message,
          severity: lastAlert.severity,
          status: 'NEW',
          created_at: new Date().toISOString()
        };
        return [newAlert, ...prev];
      });
      setKpis((prev: any) => prev ? { ...prev, total_alerts: (prev.total_alerts || 0) + 1 } : prev);
    }
  }, [lastAlert]);

  useEffect(() => {
    if (isStaffLoggedIn) {
      loadDashboardData();
      const interval = setInterval(loadDashboardData, 12000);
      return () => clearInterval(interval);
    }
  }, [isStaffLoggedIn]);

  // Handle ATM Lockdown / Unlock
  const handleLockdownAtm = async (atmId: number) => {
    try {
      await ApiService.setAtmStatus(atmId, 'LOCKDOWN', 'Manual emergency lockdown from SOC SIEM Console');
      loadDashboardData();
      if (selectedAtm && selectedAtm.id === atmId) {
        setSelectedAtm(prev => prev ? { ...prev, status: 'LOCKDOWN' } : null);
      }
    } catch (err: any) {
      alert(err.message);
    }
  };

  const handleUnlockAtm = async (atmId: number) => {
    const reason = prompt('Enter mandatory security justification for releasing lockdown:');
    if (!reason) return;
    try {
      await ApiService.unlockAtm(atmId, reason);
      loadDashboardData();
      if (selectedAtm && selectedAtm.id === atmId) {
        setSelectedAtm(prev => prev ? { ...prev, status: 'ONLINE' } : null);
      }
    } catch (err: any) {
      alert(err.message);
    }
  };

  // Handle Alert Acknowledge
  const handleAckAlert = async (alertId: number) => {
    try {
      await ApiService.acknowledgeAlert(alertId);
      loadDashboardData();
    } catch (err: any) {
      alert(err.message);
    }
  };

  // Tamper Demo
  const handleRunTamperDemo = async () => {
    try {
      const logs = await ApiService.getAuditLogs();
      if (!logs || logs.length === 0) {
        alert('No audit logs available to tamper with.');
        return;
      }
      const target = logs[logs.length - 1]; // First or oldest log
      const res = await ApiService.tamperDemo(target.id);
      setTamperedLogId(target.id);
      setTamperMsg(`Tampered Record #${res.sequence_no}: Modified action in database!`);
      // Trigger verify
      const verifyRes = await ApiService.verifyAudit();
      setAuditInfo(verifyRes);
    } catch (err: any) {
      alert(err.message);
    }
  };

  const handleRestoreTamper = async () => {
    if (!tamperedLogId) return;
    try {
      await ApiService.restoreDemo(tamperedLogId);
      setTamperMsg(null);
      setTamperedLogId(null);
      const verifyRes = await ApiService.verifyAudit();
      setAuditInfo(verifyRes);
    } catch (err: any) {
      alert(err.message);
    }
  };

  // Render Login Modal if not logged in
  if (!isStaffLoggedIn) {
    return (
      <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center p-4">
        <div className="glass-panel p-8 rounded-3xl max-w-md w-full border-slate-800 shadow-2xl space-y-6">
          <div className="text-center space-y-2">
            <div className="w-12 h-12 rounded-2xl bg-blue-600/20 border border-blue-500/40 text-blue-400 flex items-center justify-center mx-auto">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <h1 className="text-xl font-bold text-white tracking-tight">SOC SIEM Command Center</h1>
            <p className="text-xs text-slate-400">Authenticated Security Analyst Access</p>
          </div>

          {loginError && (
            <div className="p-3 bg-rose-950/60 border border-rose-500/40 text-rose-300 text-xs rounded-xl">
              {loginError}
            </div>
          )}

          <form onSubmit={handleStaffLogin} className="space-y-4">
            <div>
              <label className="text-xs text-slate-400 block mb-1 font-mono">ANALYST USERNAME</label>
              <input
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-2.5 text-white text-sm focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label className="text-xs text-slate-400 block mb-1 font-mono">STAFF PASSWORD</label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-2.5 text-white text-sm focus:outline-none focus:border-blue-500"
              />
            </div>
            <button
              type="submit"
              className="w-full py-3 bg-blue-600 hover:bg-blue-500 text-white font-bold text-sm rounded-xl shadow-lg shadow-blue-600/30 transition"
            >
              AUTHENTICATE TO SIEM
            </button>
          </form>

          <div className="space-y-3 pt-2">
            <button
              type="button"
              onClick={async () => {
                try {
                  const res = await ApiService.loginStaff('admin', 'Admin@1234');
                  ApiService.setAuth(res.access_token, { username: res.username, role: res.role });
                  setIsStaffLoggedIn(true);
                  loadDashboardData();
                } catch (err: any) {
                  alert(err.message || 'Auto-auth failed');
                }
              }}
              className="w-full btn-cyber-primary py-3 rounded-xl text-xs font-cyber font-bold tracking-wider uppercase text-black"
            >
              ⚡ 1-CLICK INSTANT ROOT ADMIN AUTHORIZATION
            </button>
            <p className="text-[11px] text-zinc-500 font-mono text-center">Pre-configured Demo Credentials: admin / Admin@1234</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-[calc(100vh-4rem)] p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto space-y-6 bg-cyber-matrix">
      {/* SIEM Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 glass-panel p-4 rounded-2xl border-slate-800">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-blue-500/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
            <Radio className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <h1 className="text-base font-bold text-white flex items-center gap-2">
              SOC Security Incident & Event Management (SIEM)
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                LIVE TELEMETRY
              </span>
            </h1>
            <p className="text-xs text-slate-400">Real-time threat detection, automated playbooks, and Leaflet ATM tracking</p>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-1.5 px-3 py-1 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono">
            <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`}></div>
            <span className={isConnected ? 'text-emerald-400' : 'text-amber-400'}>
              {isConnected ? 'WEBSOCKET: STREAMING' : 'CONNECTING...'}
            </span>
          </div>
          <button
            onClick={loadDashboardData}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg text-xs font-mono text-slate-300 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>SYNC</span>
          </button>
        </div>
      </div>

      {/* 6 Real-time KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Total ATMs */}
        <div className="glass-card p-4 rounded-2xl space-y-1">
          <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400">ATMs Fleet</span>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl font-bold text-white">{kpis?.atms?.total ?? 16}</span>
            <span className="text-xs text-emerald-400 font-mono">({kpis?.atms?.online ?? 14} online)</span>
          </div>
          <p className="text-[10px] text-rose-400 font-mono">{kpis?.atms?.lockdown ?? 0} in lockdown</p>
        </div>

        {/* Active Sessions */}
        <div className="glass-card p-4 rounded-2xl space-y-1">
          <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400">Active Sessions</span>
          <div className="text-2xl font-bold text-cyan-400 font-mono">{kpis?.active_sessions ?? 1}</div>
          <p className="text-[10px] text-slate-400 font-mono">Live customer sessions</p>
        </div>

        {/* Today Txns */}
        <div className="glass-card p-4 rounded-2xl space-y-1">
          <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400">Transactions Today</span>
          <div className="text-2xl font-bold text-white font-mono">{kpis?.today_activity?.transactions_count ?? 0}</div>
          <p className="text-[10px] text-slate-400 font-mono">INR {kpis?.today_activity?.volume_inr?.toLocaleString('en-IN') ?? '0'}</p>
        </div>

        {/* Critical Alerts */}
        <div className="glass-card p-4 rounded-2xl space-y-1 border-rose-500/30">
          <span className="text-[10px] uppercase font-mono tracking-wider text-rose-400">Critical Alerts</span>
          <div className="text-2xl font-bold text-rose-400 font-mono">{kpis?.alerts?.CRITICAL ?? 0}</div>
          <p className="text-[10px] text-slate-400 font-mono">{kpis?.alerts?.HIGH ?? 0} High Priority</p>
        </div>

        {/* Open Incidents */}
        <div className="glass-card p-4 rounded-2xl space-y-1">
          <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400">Open Incidents</span>
          <div className="text-2xl font-bold text-amber-400 font-mono">{kpis?.incidents?.open ?? 0}</div>
          <p className="text-[10px] text-slate-400 font-mono">{kpis?.incidents?.investigating ?? 0} investigating</p>
        </div>

        {/* Audit Integrity Badge */}
        <div className="glass-card p-4 rounded-2xl space-y-1">
          <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400">Audit Chain</span>
          <div className={`text-xl font-bold font-mono flex items-center gap-1.5 ${
            auditInfo?.status === 'VALID' ? 'text-emerald-400' : 'text-rose-400 animate-pulse'
          }`}>
            <span className={`w-2 h-2 rounded-full ${auditInfo?.status === 'VALID' ? 'bg-emerald-400' : 'bg-rose-500'}`} />
            <span>{auditInfo?.status ?? 'VALID'}</span>
          </div>
          <p className="text-[10px] text-slate-400 font-mono">{auditInfo?.verified_logs ?? 0} blocks verified</p>
        </div>
      </div>

      {/* Tamper Demo Alert Banner */}
      {tamperMsg && (
        <div className="p-4 bg-rose-950/80 border-2 border-rose-500/60 rounded-2xl flex items-center justify-between shadow-xl animate-pulse">
          <div className="flex items-center space-x-3">
            <AlertOctagon className="w-6 h-6 text-rose-400" />
            <div>
              <p className="text-sm font-bold text-white">CRYPTOGRAPHIC TAMPERING DETECTED BY SHA-256 AUDIT VERIFIER!</p>
              <p className="text-xs text-rose-200 font-mono">{tamperMsg}</p>
            </div>
          </div>
          <button
            onClick={handleRestoreTamper}
            className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-bold font-mono shadow"
          >
            RESTORE AUDIT INTEGRITY
          </button>
        </div>
      )}

      {/* Middle Grid: Map (Cols 7) + Analytics (Cols 5) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* ATM Map */}
        <div className="lg:col-span-7 glass-panel rounded-3xl p-5 border-slate-800 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center space-x-2">
              <MapPin className="w-4 h-4 text-blue-400" />
              <h2 className="text-sm font-bold text-white">Geographic ATM Network Map (India)</h2>
            </div>
            <span className="text-[11px] text-slate-400 font-mono">{filteredAtms.length} Terminals Displayed</span>
          </div>

          {/* Interactive Map Filter Bar */}
          <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-mono">
            {(['ALL', 'ONLINE', 'OFFLINE', 'MAINTENANCE', 'ATTACK', 'HIGH_RISK', 'LOCKDOWN'] as const).map(tab => (
              <button
                key={tab}
                onClick={() => setMapFilter(tab)}
                className={`px-2.5 py-1 rounded-lg transition flex items-center space-x-1.5 ${
                  mapFilter === tab 
                    ? 'bg-blue-600 text-white font-bold shadow-sm' 
                    : 'bg-slate-900/80 text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                <span>{tab}</span>
                <span className="px-1.5 py-0.2 rounded-full bg-slate-800 text-[9px] text-slate-300">
                  {filterCounts[tab]}
                </span>
              </button>
            ))}
          </div>

          <div className="h-[360px] rounded-2xl overflow-hidden border border-slate-800 relative z-0">
            <MapContainer
              center={[19.0760, 78.8777]}
              zoom={5}
              style={{ height: '100%', width: '100%' }}
              className="z-0"
            >
              <MapTileProvider preferredProvider="openstreetmap" />
              {filteredAtms.map(atm => (
                <Marker
                  key={atm.id}
                  position={[atm.latitude, atm.longitude]}
                  icon={createCustomMarker(atm)}
                  eventHandlers={{
                    click: () => setSelectedAtm(atm)
                  }}
                >
                  <Popup className="text-slate-900 font-sans text-xs">
                    <div className="font-bold">{atm.atm_code}</div>
                    <div>{atm.city} - {atm.address}</div>
                    <div>Status: <span className="font-semibold">{atm.status}</span></div>
                    <div>Cash: INR {atm.cash_total?.toLocaleString('en-IN')}</div>
                    <div className="mt-1 text-blue-600 font-semibold cursor-pointer">Click to inspect Security Profile &rarr;</div>
                  </Popup>
                </Marker>
              ))}
            </MapContainer>
          </div>
        </div>

        {/* Analytics Charts */}
        <div className="lg:col-span-5 glass-panel rounded-3xl p-5 border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-bold text-white">Security Threat Analytics</h2>
            </div>
            <span className="text-[11px] text-slate-400 font-mono">Pandas Engine</span>
          </div>

          <div className="h-[360px] flex flex-col justify-between gap-4">
            {/* Risk Distribution Chart */}
            <div className="flex-1 bg-slate-950/60 p-3 rounded-xl border border-slate-800">
              <p className="text-[11px] font-mono text-slate-400 mb-2">RISK SCORE DISTRIBUTION (TRANSACTIONS)</p>
              <ResponsiveContainer width="100%" height={120}>
                <BarChart data={analytics?.risk_distribution || [
                  { bracket: '0-20', count: 42 },
                  { bracket: '21-40', count: 18 },
                  { bracket: '41-60', count: 7 },
                  { bracket: '61-80', count: 3 },
                  { bracket: '81-100', count: 1 }
                ]}>
                  <XAxis dataKey="bracket" stroke="#64748b" fontSize={10} />
                  <YAxis stroke="#64748b" fontSize={10} />
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', fontSize: '11px' }} />
                  <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>

            {/* Tamper Demo Control Box */}
            <div className="bg-slate-950/80 p-3.5 rounded-xl border border-slate-800 flex items-center justify-between">
              <div>
                <p className="text-xs font-bold text-white flex items-center gap-1.5">
                  <Bug className="w-3.5 h-3.5 text-amber-400" />
                  Audit Chain Tamper Simulation
                </p>
                <p className="text-[10px] text-slate-400">Inject illegal DB modification to test SHA-256 verifier</p>
              </div>
              <button
                onClick={handleRunTamperDemo}
                className="px-3 py-1.5 bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-500/40 rounded-lg text-xs font-bold font-mono transition"
              >
                Tamper Demo
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Lower Section: Incidents Console (Cols 7) + Live Alerts Feed (Cols 5) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Incidents Queue */}
        <div className="lg:col-span-7 glass-panel rounded-3xl p-5 border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              <h2 className="text-sm font-bold text-white">Active Incident Console & Automated Playbooks</h2>
            </div>
            <span className="text-[11px] text-slate-400 font-mono">{incidents.length} Recorded</span>
          </div>

          <div className="space-y-3 max-h-[380px] overflow-y-auto pr-1">
            {incidents.length === 0 ? (
              <p className="text-xs text-slate-500 font-mono py-8 text-center">No security incidents open.</p>
            ) : (
              incidents.map(inc => (
                <div
                  key={inc.id}
                  onClick={() => setSelectedIncident(inc)}
                  className={`p-4 rounded-2xl border cursor-pointer transition ${
                    selectedIncident?.id === inc.id
                      ? 'bg-blue-600/10 border-blue-500/50'
                      : 'bg-slate-950/70 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex justify-between items-start mb-2">
                    <div className="flex items-center space-x-2">
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                        inc.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                        inc.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                        'bg-amber-500/20 text-amber-400'
                      }`}>
                        {inc.severity}
                      </span>
                      <span className="font-mono text-xs font-bold text-white">{inc.incident_code}</span>
                      {inc.is_simulated && (
                        <span className="text-[9px] bg-slate-800 text-slate-400 px-1.5 py-0.5 rounded">SIMULATED</span>
                      )}
                    </div>
                    <span className="text-[10px] font-mono text-slate-500">{new Date(inc.created_at).toLocaleTimeString()}</span>
                  </div>

                  <p className="text-xs text-slate-300 font-medium line-clamp-1">{inc.summary}</p>

                  {/* Automated Playbook Checklist preview */}
                  {inc.actions && inc.actions.length > 0 && (
                    <div className="mt-3 pt-2 border-t border-slate-900 grid grid-cols-2 gap-1 text-[11px] font-mono text-emerald-400">
                      {inc.actions.slice(0, 4).map((act, idx) => (
                        <div key={idx} className="flex items-center space-x-1 truncate">
                          <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                          <span className="truncate">{act.action_type}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Live Alerts Queue */}
        <div className="lg:col-span-5 glass-panel rounded-3xl p-5 border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 text-rose-400" />
              <h2 className="text-sm font-bold text-white">Live SIEM Alert Stream</h2>
            </div>
            <span className="text-[11px] text-slate-400 font-mono">{alerts.length} Total</span>
          </div>

          <div className="space-y-2.5 max-h-[380px] overflow-y-auto pr-1">
            {alerts.length === 0 ? (
              <p className="text-xs text-slate-500 font-mono py-8 text-center">Alert queue clear.</p>
            ) : (
              alerts.map(al => (
                <div key={al.id} className="p-3 bg-slate-950/70 border border-slate-800 rounded-xl space-y-1.5">
                  <div className="flex justify-between items-center text-xs">
                    <span className="font-bold text-white line-clamp-1">{al.title}</span>
                    <span className={`text-[10px] font-mono font-bold ${
                      al.severity === 'CRITICAL' ? 'text-rose-400' :
                      al.severity === 'HIGH' ? 'text-orange-400' : 'text-amber-400'
                    }`}>
                      {al.severity}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 line-clamp-2">{al.message}</p>
                  <div className="flex justify-between items-center pt-1 text-[10px] font-mono text-slate-500">
                    <span>{new Date(al.created_at).toLocaleTimeString()}</span>
                    {al.status === 'NEW' ? (
                      <button
                        onClick={() => handleAckAlert(al.id)}
                        className="text-blue-400 hover:text-blue-300 font-semibold"
                      >
                        Acknowledge →
                      </button>
                    ) : (
                      <span className="text-emerald-500 font-semibold">ACKNOWLEDGED</span>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* ATM Security Profile Drawer */}
      <AtmSecurityDrawer
        atm={selectedAtm as any}
        onClose={() => setSelectedAtm(null)}
        onActionComplete={loadDashboardData}
      />
    </div>
  );
};
