import React, { useState, useEffect } from 'react';
import { KeyRound, ShieldCheck, AlertCircle, RefreshCw, Lock, CheckCircle2, Clock } from 'lucide-react';
import { ApiService } from '../services/api';

interface SecretItem {
  name: string;
  category: string;
  source: string;
  algorithm: string;
  status: 'ACTIVE' | 'ROTATION_DUE' | 'EXPIRED';
  last_rotated: string;
  entropy_bits: number;
}

export const SecretsManagement: React.FC = () => {
  const [secrets, setSecrets] = useState<SecretItem[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchSecrets = async () => {
    setLoading(true);
    try {
      const data = await ApiService.getSecrets();
      setSecrets(data);
    } catch (err) {
      console.error('Failed to load secrets status:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSecrets();
  }, []);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <KeyRound className="w-6 h-6 text-purple-400" />
            Secrets Management & Entropy Audit
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Zero-exposure inventory of cryptographic keys, signing tokens, and infrastructure secrets loaded via environment isolation.
          </p>
        </div>
        <button
          onClick={fetchSecrets}
          disabled={loading}
          className="flex items-center space-x-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-sm transition border border-slate-700 font-medium"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-purple-400' : ''}`} />
          <span>Refresh Secrets Status</span>
        </button>
      </div>

      {/* Safety Notice */}
      <div className="bg-purple-950/20 border border-purple-500/30 rounded-xl p-4 flex items-center gap-3 text-xs text-purple-200">
        <Lock className="w-5 h-5 text-purple-400 shrink-0" />
        <div>
          <span className="font-bold uppercase tracking-wider">Zero-Exposure Policy</span>
          <p className="text-purple-300/80 mt-0.5">
            By design, raw secret values and private keys are never returned across API boundaries or exposed in frontend bundles. Only rotation age, entropy metrics, and algorithm status are displayed.
          </p>
        </div>
      </div>

      {/* Secrets Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-950 border-b border-slate-800 text-xs font-mono text-slate-400 uppercase">
              <tr>
                <th className="py-3 px-4">Secret Identifier</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Provider / Source</th>
                <th className="py-3 px-4">Algorithm / Standard</th>
                <th className="py-3 px-4">Entropy</th>
                <th className="py-3 px-4">Last Rotation</th>
                <th className="py-3 px-4">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {secrets.map((item, idx) => (
                <tr key={idx} className="hover:bg-slate-800/30 transition">
                  <td className="py-3.5 px-4 font-mono font-bold text-white text-xs">
                    {item.name}
                  </td>
                  <td className="py-3.5 px-4 font-mono text-xs text-slate-400">
                    {item.category}
                  </td>
                  <td className="py-3.5 px-4 font-mono text-xs text-slate-300">
                    {item.source}
                  </td>
                  <td className="py-3.5 px-4 font-mono text-xs text-purple-400">
                    {item.algorithm}
                  </td>
                  <td className="py-3.5 px-4 font-mono text-xs text-slate-200">
                    {item.entropy_bits} bits
                  </td>
                  <td className="py-3.5 px-4 font-mono text-xs text-slate-400">
                    {new Date(item.last_rotated).toLocaleDateString()}
                  </td>
                  <td className="py-3.5 px-4">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      {item.status}
                    </span>
                  </td>
                </tr>
              ))}
              {secrets.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-sm text-slate-500">
                    No secrets inventory loaded.
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
