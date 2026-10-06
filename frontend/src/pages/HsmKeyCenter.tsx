import React, { useState, useEffect } from 'react';
import { 
  Lock, RefreshCw, Key, ShieldCheck, Database, 
  RotateCw, Plus, Clock, Terminal
} from 'lucide-react';
import { ApiService } from '../services/api';

export const HsmKeyCenter: React.FC = () => {
  const [data, setData] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isRotating, setIsRotating] = useState<string | null>(null);

  const fetchHsm = async () => {
    setIsLoading(true);
    try {
      const token = ApiService.getToken();
      const res = await fetch('/api/v1/security/keys/', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const json = await res.json();
        setData(json);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRotateKey = async (keyId: string) => {
    setIsRotating(keyId);
    try {
      const token = ApiService.getToken();
      const res = await fetch(`/api/v1/security/keys/${keyId}/rotate`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        fetchHsm();
      }
    } catch (err) {
      alert('Key rotation failed.');
    } finally {
      setIsRotating(null);
    }
  };

  useEffect(() => {
    fetchHsm();
  }, []);

  const hsm = data?.hsm_status;

  return (
    <div className="min-h-[calc(100vh-4rem)] p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto space-y-6">
      {/* Banner */}
      <div className="p-3 bg-cyan-950/40 border border-cyan-500/30 rounded-2xl flex items-center justify-between text-xs text-cyan-300 font-mono">
        <div className="flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span>HARDWARE SECURITY MODULE (HSM) SIMULATION / DEVELOPMENT ENVIRONMENT</span>
        </div>
        <span className="text-[10px] text-slate-400">ENCRYPTED AT REST (AES-256-GCM)</span>
      </div>

      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 glass-panel p-5 rounded-2xl border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-white">HSM Simulator & Key Management</h1>
          <p className="text-xs text-slate-400">Cryptographic key lifecycle, automated versioning, rotation policies, and usage audit logs</p>
        </div>

        <button
          onClick={fetchHsm}
          className="p-2.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-xl text-slate-300"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* HSM Hardware Telemetry Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="glass-panel p-4 rounded-2xl border-slate-800 space-y-1">
          <span className="text-[10px] font-mono text-slate-500 uppercase">Hardware State</span>
          <div className="text-lg font-bold font-mono text-emerald-400">{hsm?.hardware_state || 'NOMINAL'}</div>
          <p className="text-[10px] text-slate-400 font-mono">Tamper: {hsm?.tamper_state || 'SECURE'}</p>
        </div>

        <div className="glass-panel p-4 rounded-2xl border-slate-800 space-y-1">
          <span className="text-[10px] font-mono text-slate-500 uppercase">Key Slots</span>
          <div className="text-lg font-bold font-mono text-cyan-400">{hsm?.used_slots || 0} / {hsm?.total_slots || 16}</div>
          <p className="text-[10px] text-slate-400 font-mono">Available slots: {(hsm?.total_slots || 16) - (hsm?.used_slots || 0)}</p>
        </div>

        <div className="glass-panel p-4 rounded-2xl border-slate-800 space-y-1">
          <span className="text-[10px] font-mono text-slate-500 uppercase">Active Keys</span>
          <div className="text-lg font-bold font-mono text-white">{hsm?.active_keys || 0} Keys</div>
          <p className="text-[10px] text-slate-400 font-mono">Rotating: {hsm?.rotating_keys || 0}</p>
        </div>

        <div className="glass-panel p-4 rounded-2xl border-slate-800 space-y-1">
          <span className="text-[10px] font-mono text-slate-500 uppercase">Master Derivation</span>
          <div className="text-sm font-bold font-mono text-purple-400 truncate">AES-256-GCM / SHA256</div>
          <p className="text-[10px] text-slate-400 font-mono">Zero-leakage envelope</p>
        </div>
      </div>

      {/* Cryptographic Keys Table */}
      <div className="glass-panel rounded-2xl border-slate-800 overflow-hidden space-y-3 p-5">
        <h2 className="text-sm font-bold text-white uppercase font-mono tracking-wider">Vault Key Inventory</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/80 text-slate-400 text-[11px] border-b border-slate-800 uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Key ID</th>
                <th className="py-3 px-4">Purpose</th>
                <th className="py-3 px-4">Algorithm</th>
                <th className="py-3 px-4">Version</th>
                <th className="py-3 px-4">Rotation Due</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-900">
              {(data?.keys || []).map((k: any) => (
                <tr key={k.key_id} className="hover:bg-slate-900/40 transition">
                  <td className="py-3 px-4 font-bold text-cyan-400">{k.key_id}</td>
                  <td className="py-3 px-4 text-slate-300">{k.purpose}</td>
                  <td className="py-3 px-4 text-purple-400">{k.algorithm}</td>
                  <td className="py-3 px-4 text-slate-400">v{k.version}</td>
                  <td className="py-3 px-4 text-slate-300">{k.rotation_due_days} days</td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      k.status === 'ACTIVE' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                      k.status === 'ROTATING' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                      'bg-slate-800 text-slate-400'
                    }`}>
                      {k.status}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right">
                    {k.status === 'ACTIVE' && (
                      <button
                        onClick={() => handleRotateKey(k.key_id)}
                        disabled={isRotating === k.key_id}
                        className="px-2.5 py-1 bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 rounded-lg text-[10px] font-bold transition flex items-center space-x-1 ml-auto"
                      >
                        <RotateCw className={`w-3 h-3 ${isRotating === k.key_id ? 'animate-spin' : ''}`} />
                        <span>ROTATE</span>
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
