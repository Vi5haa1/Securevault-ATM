import React, { useState, useEffect } from 'react';
import { ShieldCheck, Crosshair, AlertCircle, CheckCircle, Info, RefreshCw } from 'lucide-react';
import { ApiService } from '../services/api';

interface MitreTechnique {
  technique_id: string;
  technique_name: string;
  covered: boolean;
  hit_count: number;
  rules: string[];
}

interface MitreTacticGroup {
  tactic: string;
  techniques: MitreTechnique[];
}

export const MitreCoverage: React.FC = () => {
  const [tactics, setTactics] = useState<MitreTacticGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<'ALL' | 'COVERED' | 'GAPS'>('ALL');
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(null);

  const fetchCoverage = async () => {
    setLoading(true);
    try {
      const data = await ApiService.getMitreCoverage();
      setTactics(data);
    } catch (err) {
      console.error('Failed to load MITRE coverage:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCoverage();
  }, []);

  const totalTechniques = tactics.reduce((acc, t) => acc + t.techniques.length, 0);
  const coveredTechniques = tactics.reduce((acc, t) => acc + t.techniques.filter(x => x.covered).length, 0);
  const coveragePercent = totalTechniques > 0 ? Math.round((coveredTechniques / totalTechniques) * 100) : 0;
  const totalHits = tactics.reduce((acc, t) => acc + t.techniques.reduce((sum, x) => sum + x.hit_count, 0), 0);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Crosshair className="w-6 h-6 text-indigo-400" />
            MITRE ATT&CK® Defensive Mapping
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Enterprise tactic & technique matrix showing automated detection rule coverage, hit frequency, and defensive gaps.
          </p>
        </div>
        <button
          onClick={fetchCoverage}
          disabled={loading}
          className="flex items-center space-x-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-sm transition border border-slate-700 font-medium"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-indigo-400' : ''}`} />
          <span>Refresh Matrix</span>
        </button>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
          <div className="text-xs font-mono text-slate-400 uppercase">Detection Coverage</div>
          <div className="text-2xl font-bold text-indigo-400 mt-1">{coveragePercent}%</div>
          <div className="w-full bg-slate-800 rounded-full h-1.5 mt-2 overflow-hidden">
            <div className="bg-indigo-500 h-full rounded-full" style={{ width: `${coveragePercent}%` }} />
          </div>
        </div>
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
          <div className="text-xs font-mono text-slate-400 uppercase">Mapped Techniques</div>
          <div className="text-2xl font-bold text-white mt-1">
            {coveredTechniques} <span className="text-sm text-slate-500 font-normal">/ {totalTechniques}</span>
          </div>
          <div className="text-[11px] text-emerald-400 mt-1">With active detection logic</div>
        </div>
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
          <div className="text-xs font-mono text-slate-400 uppercase">Defensive Gaps</div>
          <div className="text-2xl font-bold text-amber-400 mt-1">
            {totalTechniques - coveredTechniques}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Simulated techniques without rule</div>
        </div>
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
          <div className="text-xs font-mono text-slate-400 uppercase">Total Rule Hits</div>
          <div className="text-2xl font-bold text-cyan-400 mt-1">{totalHits}</div>
          <div className="text-[11px] text-slate-400 mt-1">Live correlation events triggered</div>
        </div>
      </div>

      {/* Controls & Filter */}
      <div className="flex items-center justify-between bg-slate-900/40 p-4 rounded-xl border border-slate-800">
        <div className="flex space-x-2">
          <button
            onClick={() => setFilter('ALL')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono transition border ${
              filter === 'ALL'
                ? 'bg-indigo-600/20 text-indigo-300 border-indigo-500/40'
                : 'bg-slate-950 text-slate-400 border-slate-800 hover:border-slate-700'
            }`}
          >
            All Techniques ({totalTechniques})
          </button>
          <button
            onClick={() => setFilter('COVERED')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono transition border ${
              filter === 'COVERED'
                ? 'bg-emerald-600/20 text-emerald-300 border-emerald-500/40'
                : 'bg-slate-950 text-slate-400 border-slate-800 hover:border-slate-700'
            }`}
          >
            Covered Only ({coveredTechniques})
          </button>
          <button
            onClick={() => setFilter('GAPS')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono transition border ${
              filter === 'GAPS'
                ? 'bg-amber-600/20 text-amber-300 border-amber-500/40'
                : 'bg-slate-950 text-slate-400 border-slate-800 hover:border-slate-700'
            }`}
          >
            Defensive Gaps ({totalTechniques - coveredTechniques})
          </button>
        </div>
        <div className="text-xs font-mono text-slate-400 flex items-center gap-3">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded bg-emerald-500" /> Active Detection
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded bg-slate-800 border border-slate-700" /> Gap
          </span>
        </div>
      </div>

      {/* ATT&CK Matrix Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-4">
        {tactics.map(t => {
          const visibleTechniques = t.techniques.filter(item => {
            if (filter === 'COVERED') return item.covered;
            if (filter === 'GAPS') return !item.covered;
            return true;
          });

          return (
            <div key={t.tactic} className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden flex flex-col">
              <div className="bg-slate-950 px-4 py-3 border-b border-slate-800 flex justify-between items-center">
                <span className="font-mono text-xs font-bold text-slate-300 uppercase tracking-wider">
                  {t.tactic}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                  {t.techniques.filter(x => x.covered).length}/{t.techniques.length}
                </span>
              </div>
              <div className="p-3 space-y-2 flex-1">
                {visibleTechniques.map(tech => (
                  <div
                    key={tech.technique_id}
                    onClick={() => setSelectedTechnique(tech)}
                    className={`p-3 rounded-lg border cursor-pointer transition ${
                      tech.covered
                        ? 'bg-emerald-950/20 border-emerald-500/30 hover:border-emerald-500/60'
                        : 'bg-slate-950 border-slate-800 hover:border-slate-700 opacity-60'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-white">
                        {tech.technique_id}
                      </span>
                      {tech.covered ? (
                        <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400">
                          {tech.hit_count} hits
                        </span>
                      ) : (
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-500">
                          GAP
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-slate-300 font-medium mt-1">
                      {tech.technique_name}
                    </div>
                    {tech.rules.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {tech.rules.map(r => (
                          <span key={r} className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                            {r}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
                {visibleTechniques.length === 0 && (
                  <div className="text-center py-6 text-xs text-slate-500 font-mono">
                    No techniques in this filter
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Selected Technique Detail Modal */}
      {selectedTechnique && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 space-y-4">
            <div className="flex justify-between items-start">
              <div>
                <span className="font-mono text-xs text-indigo-400 uppercase font-semibold">ATT&CK Technique Detail</span>
                <h3 className="text-lg font-bold text-white mt-1">
                  {selectedTechnique.technique_id}: {selectedTechnique.technique_name}
                </h3>
              </div>
              <button
                onClick={() => setSelectedTechnique(null)}
                className="text-slate-400 hover:text-white font-mono text-sm px-2 py-1"
              >
                ✕
              </button>
            </div>
            <div className="space-y-3 text-sm">
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <span className="text-xs text-slate-400 block font-mono">Coverage Status:</span>
                <span className={`font-mono font-bold ${selectedTechnique.covered ? 'text-emerald-400' : 'text-amber-400'}`}>
                  {selectedTechnique.covered ? 'COVERED BY ACTIVE RULE' : 'GAP - NO DEDICATED RULE'}
                </span>
              </div>
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <span className="text-xs text-slate-400 block font-mono">Mapped Rules:</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {selectedTechnique.rules.length > 0 ? (
                    selectedTechnique.rules.map(r => (
                      <span key={r} className="px-2 py-1 rounded bg-indigo-500/20 text-indigo-300 font-mono text-xs border border-indigo-500/30">
                        {r}
                      </span>
                    ))
                  ) : (
                    <span className="text-xs text-slate-500 italic">None</span>
                  )}
                </div>
              </div>
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <span className="text-xs text-slate-400 block font-mono">Triggered Hit Count:</span>
                <span className="font-mono text-cyan-400 font-bold">{selectedTechnique.hit_count} events correlated</span>
              </div>
            </div>
            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedTechnique(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-sm font-medium transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
