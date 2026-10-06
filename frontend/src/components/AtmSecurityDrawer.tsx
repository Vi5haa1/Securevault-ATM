import React, { useState } from 'react';
import { 
  X, ShieldAlert, ShieldCheck, AlertTriangle, Activity, 
  Cpu, HardDrive, Wifi, Lock, Unlock, Key, FileCode2,
  RefreshCw, CheckCircle2, AlertOctagon, Terminal
} from 'lucide-react';
import { ApiService } from '../services/api';

export interface AtmProfileData {
  id: number;
  atm_code: string;
  city: string;
  address: string;
  status: string;
  network_status: string;
  cash_total: number;
  security_status: string;
  risk_score: number;
  firmware_version?: string;
  firmware_hash?: string;
  secure_boot_enabled?: boolean;
  certificate_id?: string;
  certificate_status?: string;
  latency_ms?: number;
  cpu_usage?: number;
  memory_usage?: number;
  disk_usage?: number;
  under_attack?: boolean;
  active_alerts_count?: number;
  open_incidents_count?: number;
  sensors?: Record<string, string>;
  last_heartbeat?: string;
}

interface AtmSecurityDrawerProps {
  atm: AtmProfileData | null;
  onClose: () => void;
  onActionComplete: () => void;
}

export const AtmSecurityDrawer: React.FC<AtmSecurityDrawerProps> = ({
  atm,
  onClose,
  onActionComplete
}) => {
  const [actionReason, setActionReason] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  if (!atm) return null;

  const currentUser = ApiService.getCurrentUser();
  const canModifyState = currentUser && ['SECURITY_ANALYST', 'BANK_ADMIN', 'SUPER_ADMIN'].includes(currentUser.role);

  const handleStatusChange = async (newStatus: 'ONLINE' | 'LOCKDOWN' | 'MAINTENANCE') => {
    if (!actionReason.trim()) {
      setErrorMsg('A documented operational or security reason is strictly required.');
      return;
    }
    setIsSubmitting(true);
    setErrorMsg(null);
    try {
      await ApiService.setAtmStatus(atm.id, newStatus, actionReason);
      setActionReason('');
      onActionComplete();
    } catch (err: any) {
      setErrorMsg(err.message || 'Action failed.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const isLockdown = atm.status === 'LOCKDOWN';
  const isAttack = atm.under_attack || isLockdown;

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full max-w-md bg-slate-950/95 backdrop-blur-xl border-l border-slate-800 shadow-2xl flex flex-col animate-in slide-in-from-right duration-200">
      {/* Header */}
      <div className="p-5 border-b border-slate-800 flex items-start justify-between bg-slate-900/50">
        <div>
          <div className="flex items-center space-x-2">
            <span className="font-mono text-xs px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">
              {atm.city}
            </span>
            <span className={`font-mono text-xs px-2 py-0.5 rounded font-bold ${
              atm.status === 'ONLINE' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
              atm.status === 'LOCKDOWN' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30 animate-pulse' :
              'bg-amber-500/20 text-amber-400 border border-amber-500/30'
            }`}>
              {atm.status}
            </span>
            {isAttack && (
              <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-rose-500 text-white font-bold animate-ping">
                ALERT
              </span>
            )}
          </div>
          <h2 className="text-lg font-bold text-white mt-1">{atm.atm_code}</h2>
          <p className="text-xs text-slate-400">{atm.address}</p>
        </div>
        <button 
          onClick={onClose}
          className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-5 space-y-6">
        {/* Threat & Security Posture Card */}
        <div className="glass-panel p-4 rounded-2xl border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Security State</span>
            <span className={`text-xs font-mono font-bold ${
              atm.risk_score > 60 ? 'text-rose-400' : atm.risk_score > 30 ? 'text-amber-400' : 'text-emerald-400'
            }`}>
              Risk Score: {atm.risk_score}/100
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800">
              <span className="text-[10px] text-slate-500 block font-mono">ACTIVE ALERTS</span>
              <span className={`text-base font-bold font-mono ${atm.active_alerts_count ? 'text-rose-400' : 'text-slate-300'}`}>
                {atm.active_alerts_count ?? 0}
              </span>
            </div>
            <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800">
              <span className="text-[10px] text-slate-500 block font-mono">OPEN INCIDENTS</span>
              <span className={`text-base font-bold font-mono ${atm.open_incidents_count ? 'text-rose-400' : 'text-slate-300'}`}>
                {atm.open_incidents_count ?? 0}
              </span>
            </div>
          </div>
        </div>

        {/* Cryptographic & Firmware Integrity */}
        <div className="glass-panel p-4 rounded-2xl border-slate-800 space-y-3">
          <div className="flex items-center space-x-2 text-cyan-400">
            <FileCode2 className="w-4 h-4" />
            <h3 className="text-xs font-bold text-white uppercase font-mono tracking-wider">Firmware & Cryptography</h3>
          </div>

          <div className="space-y-2 text-xs font-mono">
            <div className="flex justify-between py-1 border-b border-slate-900">
              <span className="text-slate-400">Firmware Build:</span>
              <span className="text-slate-200">{atm.firmware_version || 'SV-ATM-FW-3.4.1'}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-900">
              <span className="text-slate-400">Secure Boot:</span>
              <span className={atm.secure_boot_enabled !== false ? 'text-emerald-400' : 'text-rose-400'}>
                {atm.secure_boot_enabled !== false ? 'ENABLED (Verified)' : 'DISABLED (Breached)'}
              </span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-900">
              <span className="text-slate-400">X.509 Certificate:</span>
              <span className={atm.certificate_status === 'VALID' ? 'text-emerald-400' : 'text-rose-400'}>
                {atm.certificate_id} ({atm.certificate_status || 'VALID'})
              </span>
            </div>
            <div>
              <span className="text-slate-500 text-[10px] block">MANIFEST SHA-256 HASH</span>
              <p className="text-[10px] text-slate-400 break-all bg-slate-950 p-2 rounded-lg border border-slate-800">
                {atm.firmware_hash || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
              </p>
            </div>
          </div>
        </div>

        {/* Telemetry & Health Gauges */}
        <div className="glass-panel p-4 rounded-2xl border-slate-800 space-y-3">
          <div className="flex items-center space-x-2 text-purple-400">
            <Activity className="w-4 h-4" />
            <h3 className="text-xs font-bold text-white uppercase font-mono tracking-wider">Health Telemetry</h3>
          </div>

          <div className="space-y-3 text-xs">
            {/* CPU */}
            <div>
              <div className="flex justify-between text-slate-400 mb-1 font-mono text-[11px]">
                <span>CPU Load</span>
                <span>{atm.cpu_usage ?? 18}%</span>
              </div>
              <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
                <div 
                  className={`h-full ${atm.cpu_usage && atm.cpu_usage > 75 ? 'bg-rose-500' : 'bg-cyan-500'}`} 
                  style={{ width: `${atm.cpu_usage ?? 18}%` }} 
                />
              </div>
            </div>

            {/* Memory */}
            <div>
              <div className="flex justify-between text-slate-400 mb-1 font-mono text-[11px]">
                <span>Memory Utilization</span>
                <span>{atm.memory_usage ?? 32}%</span>
              </div>
              <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-purple-500" 
                  style={{ width: `${atm.memory_usage ?? 32}%` }} 
                />
              </div>
            </div>

            {/* Disk & Network */}
            <div className="grid grid-cols-2 gap-2 pt-1 font-mono text-[11px]">
              <div className="bg-slate-900 p-2 rounded-xl border border-slate-800 flex justify-between">
                <span className="text-slate-500">Latency</span>
                <span className="text-emerald-400">{atm.latency_ms ?? 24} ms</span>
              </div>
              <div className="bg-slate-900 p-2 rounded-xl border border-slate-800 flex justify-between">
                <span className="text-slate-500">Cash Vault</span>
                <span className="text-slate-200">INR {atm.cash_total?.toLocaleString('en-IN')}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Permitted Actions (RBAC Gated) */}
        {canModifyState && (
          <div className="glass-panel p-4 rounded-2xl border-slate-800 space-y-3">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block">Security Command & Control</span>

            {errorMsg && (
              <p className="text-xs text-rose-400 bg-rose-500/10 border border-rose-500/20 p-2 rounded-xl">
                {errorMsg}
              </p>
            )}

            <div>
              <label className="text-[10px] text-slate-400 font-mono block mb-1">
                ACTION AUDIT REASON (MANDATORY)
              </label>
              <input
                type="text"
                placeholder="e.g. Cleared hardware technician inspection ticket #4810"
                value={actionReason}
                onChange={e => setActionReason(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-white text-xs focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="space-y-2 pt-1">
              {isLockdown ? (
                <button
                  disabled={isSubmitting}
                  onClick={() => handleStatusChange('ONLINE')}
                  className="w-full py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs rounded-xl shadow-lg shadow-emerald-600/20 transition flex items-center justify-center space-x-2"
                >
                  <Unlock className="w-4 h-4" />
                  <span>RELEASE FROM EMERGENCY LOCKDOWN</span>
                </button>
              ) : (
                <button
                  disabled={isSubmitting}
                  onClick={() => handleStatusChange('LOCKDOWN')}
                  className="w-full py-2.5 bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs rounded-xl shadow-lg shadow-rose-600/20 transition flex items-center justify-center space-x-2"
                >
                  <Lock className="w-4 h-4" />
                  <span>INITIATE EMERGENCY LOCKDOWN</span>
                </button>
              )}

              {atm.status !== 'MAINTENANCE' && !isLockdown && (
                <button
                  disabled={isSubmitting}
                  onClick={() => handleStatusChange('MAINTENANCE')}
                  className="w-full py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs rounded-xl transition"
                >
                  SET TO MAINTENANCE MODE
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
