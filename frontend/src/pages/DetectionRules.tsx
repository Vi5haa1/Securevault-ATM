import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, Plus, Play, CheckCircle2, XCircle, 
  RefreshCw, Edit3, Eye, FileText, ToggleLeft, ToggleRight, X
} from 'lucide-react';
import { ApiService } from '../services/api';

export const DetectionRules: React.FC = () => {
  const [rules, setRules] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [selectedRule, setSelectedRule] = useState<any | null>(null);
  const [testResult, setTestResult] = useState<any | null>(null);
  const [sampleEventJson, setSampleEventJson] = useState('{\n  "type": "FAILED_PIN",\n  "count": 5,\n  "atm_code": "SV-ATM-CHE-101"\n}');
  const [isTesting, setIsTesting] = useState(false);

  const fetchRules = async () => {
    setIsLoading(true);
    try {
      const token = ApiService.getToken();
      const res = await fetch('/api/v1/soc/rules/', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setRules(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  const toggleRule = async (ruleId: string) => {
    try {
      const token = ApiService.getToken();
      const res = await fetch(`/api/v1/soc/rules/${ruleId}/toggle`, {
        method: 'PATCH',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        fetchRules();
      }
    } catch (err) {
      alert('Toggle failed.');
    }
  };

  const handleDryRunTest = async (ruleId: string) => {
    setIsTesting(true);
    setTestResult(null);
    try {
      const token = ApiService.getToken();
      let parsed = {};
      try {
        parsed = JSON.parse(sampleEventJson);
      } catch {
        alert('Invalid JSON in sample event.');
        setIsTesting(false);
        return;
      }

      const res = await fetch(`/api/v1/soc/rules/${ruleId}/test`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ sample_event: parsed })
      });
      if (res.ok) {
        const data = await res.json();
        setTestResult(data);
      }
    } catch (err) {
      alert('Test evaluation failed.');
    } finally {
      setIsTesting(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  return (
    <div className="min-h-[calc(100vh-4rem)] p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 glass-panel p-5 rounded-2xl border-slate-800">
        <div>
          <div className="flex items-center space-x-2">
            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-purple-500/20 text-purple-400 border border-purple-500/30">
              SIEM RULE MANAGEMENT
            </span>
            <span className="text-xs text-slate-400 font-mono">DATABASE-BACKED DATA DSL</span>
          </div>
          <h1 className="text-xl font-bold text-white mt-1">Detection Rule Engine</h1>
          <p className="text-xs text-slate-400">Database-managed detection logic with versioning, diff audits, and dry-run test suite</p>
        </div>

        <button
          onClick={fetchRules}
          className="p-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-xl text-slate-300"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Rules Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {rules.map(rule => {
          const isCritical = rule.severity === 'CRITICAL';
          return (
            <div 
              key={rule.rule_id}
              className="glass-panel p-5 rounded-2xl border-slate-800 flex flex-col justify-between space-y-4 hover:border-slate-700 transition"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-cyan-400">{rule.rule_id}</span>
                  <div className="flex items-center space-x-2">
                    <span className="text-[10px] font-mono text-slate-500">v{rule.version}</span>
                    <button 
                      onClick={() => toggleRule(rule.rule_id)}
                      className={`text-xs ${rule.enabled ? 'text-emerald-400' : 'text-slate-500'}`}
                      title={rule.enabled ? 'Enabled' : 'Disabled'}
                    >
                      {rule.enabled ? <ToggleRight className="w-5 h-5" /> : <ToggleLeft className="w-5 h-5" />}
                    </button>
                  </div>
                </div>

                <h3 className="text-sm font-bold text-white leading-tight">{rule.name}</h3>
                <p className="text-xs text-slate-400 line-clamp-2">{rule.description}</p>
              </div>

              <div className="space-y-3 pt-2 border-t border-slate-900 text-xs font-mono">
                <div className="flex justify-between text-[11px]">
                  <span className="text-slate-500">Severity:</span>
                  <span className={isCritical ? 'text-rose-400 font-bold' : 'text-amber-400 font-bold'}>
                    {rule.severity}
                  </span>
                </div>
                <div className="flex justify-between text-[11px]">
                  <span className="text-slate-500">Hits Recorded:</span>
                  <span className="text-white font-bold">{rule.hit_count} hits</span>
                </div>
                <div className="flex justify-between text-[11px]">
                  <span className="text-slate-500">MITRE:</span>
                  <span className="text-purple-400 truncate max-w-[160px]">{rule.mitre_technique}</span>
                </div>

                <div className="pt-2 flex items-center space-x-2">
                  <button
                    onClick={() => { setSelectedRule(rule); setTestResult(null); }}
                    className="flex-1 py-1.5 bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 rounded-lg text-[11px] font-bold transition flex items-center justify-center space-x-1"
                  >
                    <Play className="w-3 h-3" />
                    <span>DRY-RUN TEST</span>
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Dry Run Test Modal */}
      {selectedRule && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-xl bg-slate-900 border border-slate-800 rounded-3xl p-6 space-y-4 shadow-2xl">
            <div className="flex justify-between items-start">
              <div>
                <span className="text-xs font-mono text-cyan-400 font-bold">{selectedRule.rule_id}</span>
                <h3 className="text-base font-bold text-white">{selectedRule.name}</h3>
              </div>
              <button onClick={() => setSelectedRule(null)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-2">
              <label className="text-xs font-mono text-slate-400 block">TEST SAMPLE EVENT (JSON)</label>
              <textarea
                rows={4}
                value={sampleEventJson}
                onChange={e => setSampleEventJson(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 font-mono text-xs text-white focus:outline-none focus:border-blue-500"
              />
            </div>

            <button
              onClick={() => handleDryRunTest(selectedRule.rule_id)}
              disabled={isTesting}
              className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs rounded-xl transition flex items-center justify-center space-x-2 shadow-lg shadow-blue-600/20"
            >
              <Play className="w-4 h-4" />
              <span>{isTesting ? 'EVALUATING DRY-RUN...' : 'EVALUATE RULE AGAINST SAMPLE'}</span>
            </button>

            {testResult && (
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-xs font-mono">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">VERDICT:</span>
                  <span className={`px-2 py-0.5 rounded font-bold ${
                    testResult.verdict === 'TRIGGERED' ? 'bg-rose-500/20 text-rose-400' : 'bg-slate-800 text-slate-400'
                  }`}>
                    {testResult.verdict}
                  </span>
                </div>
                <div className="text-slate-400">
                  <span>Actions that would execute: </span>
                  <span className="text-cyan-400">{testResult.actions_that_would_execute.join(', ') || 'None'}</span>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
