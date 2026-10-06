import React, { useState, useEffect } from 'react';
import { 
  Server, ShieldAlert, ShieldCheck, Lock, Unlock, 
  RefreshCw, CheckCircle2, AlertTriangle, Layers
} from 'lucide-react';
import { ApiService } from '../services/api';

export const ApiSecurity: React.FC = () => {
  const [data, setData] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [filterText, setFilterText] = useState('');

  const fetchInventory = async () => {
    setIsLoading(true);
    try {
      const token = ApiService.getToken();
      const res = await fetch('/api/v1/security/api/inventory', {
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

  useEffect(() => {
    fetchInventory();
  }, []);

  const routes = (data?.routes || []).filter((r: any) => 
    r.path.toLowerCase().includes(filterText.toLowerCase()) ||
    r.owasp_top_10.toLowerCase().includes(filterText.toLowerCase())
  );

  return (
    <div className="min-h-[calc(100vh-4rem)] p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto space-y-6">
      {/* Banner */}
      <div className="p-3 bg-blue-950/40 border border-blue-500/30 rounded-2xl flex items-center justify-between text-xs text-blue-300 font-mono">
        <div className="flex items-center space-x-2">
          <Server className="w-4 h-4 text-cyan-400" />
          <span>OWASP API SECURITY TOP 10 (2023) INVENTORY & RATE CONTROL</span>
        </div>
        <span className="text-[10px] text-slate-400">DISCOVERED FROM FASTAPI ROUTER</span>
      </div>

      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 glass-panel p-5 rounded-2xl border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-white">API Security Center & Inventory</h1>
          <p className="text-xs text-slate-400">Automated endpoint discovery, BOLA/IDOR object isolation, and token bucket rate throttling</p>
        </div>

        <button
          onClick={fetchInventory}
          className="p-2.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-xl text-slate-300"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="glass-panel p-4 rounded-2xl border-slate-800 space-y-1 font-mono">
          <span className="text-[10px] text-slate-500 uppercase">Total Endpoints</span>
          <div className="text-2xl font-bold text-white">{data?.total_endpoints || 0}</div>
          <p className="text-[10px] text-slate-400">Active ASGI routes</p>
        </div>

        <div className="glass-panel p-4 rounded-2xl border-slate-800 space-y-1 font-mono">
          <span className="text-[10px] text-slate-500 uppercase">Authenticated</span>
          <div className="text-2xl font-bold text-cyan-400">{data?.authenticated_endpoints || 0}</div>
          <p className="text-[10px] text-slate-400">JWT & Session bound</p>
        </div>

        <div className="glass-panel p-4 rounded-2xl border-slate-800 space-y-1 font-mono">
          <span className="text-[10px] text-slate-500 uppercase">Public Endpoints</span>
          <div className="text-2xl font-bold text-slate-400">{data?.public_endpoints || 0}</div>
          <p className="text-[10px] text-slate-400">Health & Docs only</p>
        </div>

        <div className="glass-panel p-4 rounded-2xl border-slate-800 space-y-1 font-mono">
          <span className="text-[10px] text-slate-500 uppercase">Rate Protection</span>
          <div className="text-2xl font-bold text-emerald-400">Active</div>
          <p className="text-[10px] text-slate-400">Token Bucket Filter</p>
        </div>
      </div>

      {/* Endpoint Table */}
      <div className="glass-panel rounded-2xl border-slate-800 overflow-hidden space-y-4 p-5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-bold text-white uppercase font-mono tracking-wider">Discovered API Inventory</h2>
          <input
            type="text"
            placeholder="Filter by path or OWASP category..."
            value={filterText}
            onChange={e => setFilterText(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono w-72"
          />
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/80 text-slate-400 text-[11px] border-b border-slate-800 uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">HTTP Method</th>
                <th className="py-3 px-4">Endpoint Path</th>
                <th className="py-3 px-4">Authentication</th>
                <th className="py-3 px-4">OWASP Classification</th>
                <th className="py-3 px-4">Rate Limit</th>
                <th className="py-3 px-4 text-right">Risk Tier</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-900">
              {routes.map((r: any, idx: number) => (
                <tr key={idx} className="hover:bg-slate-900/40 transition">
                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30 text-[10px] font-bold">
                      {r.methods.join(', ')}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-white font-semibold">{r.path}</td>
                  <td className="py-3 px-4">
                    {r.auth_required ? (
                      <span className="text-emerald-400 flex items-center space-x-1">
                        <Lock className="w-3.5 h-3.5" />
                        <span>Bearer JWT</span>
                      </span>
                    ) : (
                      <span className="text-slate-500 flex items-center space-x-1">
                        <Unlock className="w-3.5 h-3.5" />
                        <span>Public</span>
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-purple-400">{r.owasp_top_10}</td>
                  <td className="py-3 px-4 text-slate-300">{r.rate_limit}</td>
                  <td className="py-3 px-4 text-right">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      r.risk_tier === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400' :
                      r.risk_tier === 'HIGH' ? 'bg-amber-500/20 text-amber-400' :
                      'bg-slate-800 text-slate-400'
                    }`}>
                      {r.risk_tier}
                    </span>
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
