import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, ShieldAlert, AlertTriangle, CheckCircle2, 
  XCircle, RefreshCw, Terminal, Sliders
} from 'lucide-react';
import { ApiService } from '../services/api';

export const SecurityScanner: React.FC = () => {
  const [scannerData, setScannerData] = useState<any | null>(null);
  const [simulateMissing, setSimulateMissing] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const runScanner = async () => {
    setIsLoading(true);
    try {
      const token = ApiService.getToken();
      const res = await fetch(`/api/v1/security/scanner?simulate_missing_header=${simulateMissing}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const json = await res.json();
        setScannerData(json);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    runScanner();
  }, [simulateMissing]);

  return (
    <div className="min-h-[calc(100vh-4rem)] p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto space-y-6">
      {/* Banner */}
      <div className="p-3 bg-blue-950/40 border border-blue-500/30 rounded-2xl flex items-center justify-between text-xs text-blue-300 font-mono">
        <div className="flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span>SECUREVAULT SECURITY SCANNER (Automated Endpoint & Header Inspection)</span>
        </div>
        <span className="text-[10px] text-slate-400">REAL SELF-CHECKS ENGINE</span>
      </div>

      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 glass-panel p-5 rounded-2xl border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-white">Security Scanner & Headers Inspector</h1>
          <p className="text-xs text-slate-400">Live dynamic evaluation of HTTP defense headers, transport ciphers, and bundle leakage</p>
        </div>

        <div className="flex items-center space-x-4">
          <div className="text-right font-mono">
            <span className="text-[10px] text-slate-500 uppercase">SCANNER RATING</span>
            <div className="text-2xl font-bold text-cyan-400">
              {scannerData?.scanner_score ?? 100}% PASS
            </div>
          </div>
          <button
            onClick={runScanner}
            className="p-2.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-xl text-slate-300"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Controlled Demo Failure Toggle */}
      <div className="glass-panel p-4 rounded-2xl border-slate-800 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <Sliders className="w-5 h-5 text-purple-400" />
          <div>
            <h3 className="text-sm font-bold text-white">Controlled Demo Failure Simulation</h3>
            <p className="text-xs text-slate-400">Toggle missing Content-Security-Policy (CSP) header to test scanner remediation workflow</p>
          </div>
        </div>
        <button
          onClick={() => setSimulateMissing(!simulateMissing)}
          className={`px-4 py-2 rounded-xl text-xs font-mono font-bold transition ${
            simulateMissing 
              ? 'bg-rose-600 text-white shadow-lg shadow-rose-600/30' 
              : 'bg-slate-900 text-slate-300 border border-slate-700 hover:border-slate-500'
          }`}
        >
          {simulateMissing ? 'SIMULATING MISSING CSP (CLICK TO FIX)' : 'SIMULATE MISSING HEADER'}
        </button>
      </div>

      {/* Checks Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {(scannerData?.checks || []).map((c: any, idx: number) => {
          const isPass = c.status === 'PASS';
          return (
            <div 
              key={idx}
              className={`p-5 rounded-2xl border flex flex-col justify-between space-y-3 transition ${
                isPass 
                  ? 'bg-slate-950/60 border-slate-800' 
                  : 'bg-rose-950/20 border-rose-500/40 animate-pulse'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-white font-mono">{c.check}</span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                  isPass ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                  'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                }`}>
                  {c.status}
                </span>
              </div>

              <div className="space-y-1 font-mono text-xs">
                <span className="text-slate-500 text-[10px] block">OBSERVED VALUE</span>
                <p className="p-2 rounded-lg bg-slate-900/80 border border-slate-800 text-slate-300 text-[11px] break-all">
                  {c.value}
                </p>
              </div>

              <div className="pt-2 border-t border-slate-900 text-[11px] font-sans text-slate-400">
                <span className="font-mono text-cyan-400 font-bold">Remediation: </span>
                <span>{c.remediation}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
