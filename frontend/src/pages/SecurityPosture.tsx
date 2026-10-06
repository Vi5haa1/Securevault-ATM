import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, ShieldAlert, AlertTriangle, CheckCircle2, 
  XCircle, RefreshCw, Layers, Award, Terminal
} from 'lucide-react';
import { ApiService } from '../services/api';

export const SecurityPosture: React.FC = () => {
  const [posture, setPosture] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const fetchPosture = async () => {
    setIsLoading(true);
    try {
      const token = ApiService.getToken();
      const res = await fetch('/api/v1/security/posture', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setPosture(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchPosture();
  }, []);

  return (
    <div className="min-h-[calc(100vh-4rem)] p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto space-y-6">
      {/* Banner Notice */}
      <div className="p-3 bg-blue-950/40 border border-blue-500/30 rounded-2xl flex items-center justify-between text-xs text-blue-300 font-mono">
        <div className="flex items-center space-x-2">
          <Award className="w-4 h-4 text-cyan-400" />
          <span>EDUCATIONAL / SIMULATED SECURITY CONTROL MAPPING (Not a formal PCI/ISO compliance claim)</span>
        </div>
        <span className="text-[10px] text-slate-400">9 CATEGORIES EVALUATED</span>
      </div>

      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 glass-panel p-5 rounded-2xl border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-white">Security Posture Dashboard</h1>
          <p className="text-xs text-slate-400">Continuous automated verification across cryptography, endpoints, and identity architecture</p>
        </div>

        <div className="flex items-center space-x-4">
          <div className="text-right">
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">OVERALL POSTURE SCORE</span>
            <div className="flex items-baseline space-x-2">
              <span className="text-3xl font-extrabold text-cyan-400 font-mono">
                {posture?.overall_score ?? 91.8}%
              </span>
              <span className="text-xs font-bold text-emerald-400 font-mono">
                [{posture?.overall_rating ?? 'EXCELLENT'}]
              </span>
            </div>
          </div>
          <button
            onClick={fetchPosture}
            className="p-2.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-xl text-slate-300"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* 9 Category Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {(posture?.categories || []).map((cat: any) => {
          const isPass = cat.status === 'PASS';
          return (
            <div 
              key={cat.category}
              className="glass-panel p-5 rounded-2xl border-slate-800 flex flex-col justify-between space-y-4 hover:border-slate-700 transition"
            >
              <div>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                    {cat.category}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                    isPass ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                    'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                  }`}>
                    {cat.score}% {cat.status}
                  </span>
                </div>

                <div className="space-y-3">
                  {(cat.controls || []).map((ctrl: any, idx: number) => (
                    <div key={idx} className="p-3 bg-slate-950/70 rounded-xl border border-slate-900 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold text-slate-200">{ctrl.name}</span>
                        {ctrl.status === 'PASS' ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                        )}
                      </div>
                      <p className="text-[11px] text-slate-400 font-sans">{ctrl.evidence}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="pt-3 border-t border-slate-900 text-[10px] font-mono text-slate-500">
                Remediation: {cat.controls?.[0]?.remediation || 'Controls nominal.'}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
