import React, { useState, useEffect } from 'react';
import { ShieldAlert, Search, AlertTriangle, Globe, Database, ExternalLink, RefreshCw } from 'lucide-react';
import { ApiService } from '../services/api';

interface ThreatIndicator {
  id: number;
  indicator: string;
  type: string;
  category: string;
  confidence: number;
  description: string;
  is_active: boolean;
  first_seen: string;
  last_seen: string;
}

export const ThreatIntel: React.FC = () => {
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');

  const fetchThreats = async () => {
    setLoading(true);
    try {
      const data = await ApiService.getThreats();
      setIndicators(data);
    } catch (err) {
      console.error('Failed to load threats:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();
  }, []);

  const categories = ['ALL', 'TOR_EXIT_NODE', 'CARD_TESTING_BOTNET', 'COMMAND_AND_CONTROL', 'CREDENTIAL_STUFFING'];

  const filtered = indicators.filter(item => {
    const matchesSearch = item.indicator.toLowerCase().includes(search.toLowerCase()) ||
                          item.description.toLowerCase().includes(search.toLowerCase()) ||
                          item.type.toLowerCase().includes(search.toLowerCase());
    const matchesCat = selectedCategory === 'ALL' || item.category === selectedCategory;
    return matchesSearch && matchesCat;
  });

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Educational Banner */}
      <div className="bg-amber-950/40 border border-amber-500/30 rounded-xl p-4 flex items-center justify-between text-xs text-amber-200">
        <div className="flex items-center space-x-3">
          <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
          <div>
            <span className="font-bold uppercase tracking-wider">Synthetic Threat Intelligence Feed</span>
            <p className="text-amber-300/80 mt-0.5">
              All indicators, C2 addresses, and reputation scores are entirely synthetic and modeled for defensive ATM correlation testing.
            </p>
          </div>
        </div>
        <span className="px-2.5 py-1 bg-amber-500/20 rounded font-mono text-[11px] font-semibold border border-amber-500/30">
          DEFENSIVE TEST DATA
        </span>
      </div>

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Globe className="w-6 h-6 text-cyan-400" />
            Threat Intelligence Center
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Local synthetic indicators correlated in real-time during incoming ATM transaction and security event pipeline checks.
          </p>
        </div>
        <button
          onClick={fetchThreats}
          disabled={loading}
          className="flex items-center space-x-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-sm transition border border-slate-700 font-medium"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
          <span>Refresh Indicators</span>
        </button>
      </div>

      {/* Stats Summary */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
          <div className="text-xs font-mono text-slate-400 uppercase">Active Indicators</div>
          <div className="text-2xl font-bold text-white mt-1">{indicators.filter(i => i.is_active).length}</div>
          <div className="text-[11px] text-cyan-400 mt-1">Offline defensive cache</div>
        </div>
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
          <div className="text-xs font-mono text-slate-400 uppercase">High Confidence (&gt;80%)</div>
          <div className="text-2xl font-bold text-rose-400 mt-1">
            {indicators.filter(i => i.confidence >= 80).length}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Auto-flag in pipeline</div>
        </div>
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
          <div className="text-xs font-mono text-slate-400 uppercase">IP Indicators</div>
          <div className="text-2xl font-bold text-amber-400 mt-1">
            {indicators.filter(i => i.type === 'IP').length}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Monitored for proxy/VPN abuse</div>
        </div>
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
          <div className="text-xs font-mono text-slate-400 uppercase">Pipeline Match Action</div>
          <div className="text-2xl font-bold text-purple-400 mt-1">+25 Risk</div>
          <div className="text-[11px] text-slate-400 mt-1">Applied to risk engine score</div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col md:flex-row gap-4 justify-between bg-slate-900/40 p-4 rounded-xl border border-slate-800">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
          <input
            type="text"
            placeholder="Search indicator, IP, domain, description..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
        <div className="flex gap-2 overflow-x-auto pb-1">
          {categories.map(cat => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono whitespace-nowrap transition border ${
                selectedCategory === cat
                  ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
                  : 'bg-slate-950 text-slate-400 border-slate-800 hover:border-slate-700'
              }`}
            >
              {cat.replace(/_/g, ' ')}
            </button>
          ))}
        </div>
      </div>

      {/* Indicators Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-950 border-b border-slate-800 text-xs font-mono text-slate-400 uppercase">
              <tr>
                <th className="py-3 px-4">Indicator</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">Description</th>
                <th className="py-3 px-4">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filtered.map(item => (
                <tr key={item.id} className="hover:bg-slate-800/30 transition">
                  <td className="py-3.5 px-4 font-mono font-bold text-white flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-cyan-400" />
                    {item.indicator}
                  </td>
                  <td className="py-3.5 px-4">
                    <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 border border-slate-700 text-slate-300">
                      {item.type}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 font-mono text-xs text-slate-300">
                    {item.category}
                  </td>
                  <td className="py-3.5 px-4">
                    <div className="flex items-center space-x-2">
                      <div className="w-16 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                        <div
                          className={`h-full rounded-full ${
                            item.confidence >= 80 ? 'bg-rose-500' : item.confidence >= 50 ? 'bg-amber-400' : 'bg-emerald-400'
                          }`}
                          style={{ width: `${item.confidence}%` }}
                        />
                      </div>
                      <span className="text-xs font-mono font-bold text-slate-200">{item.confidence}%</span>
                    </div>
                  </td>
                  <td className="py-3.5 px-4 text-xs text-slate-400 max-w-md">
                    {item.description}
                  </td>
                  <td className="py-3.5 px-4">
                    <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-semibold ${
                      item.is_active
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                        : 'bg-slate-800 text-slate-500'
                    }`}>
                      {item.is_active ? 'ACTIVE' : 'INACTIVE'}
                    </span>
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-sm text-slate-500">
                    No threat indicators match your search criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
