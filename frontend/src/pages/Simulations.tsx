import React, { useState, useEffect } from 'react';
import { 
  Terminal, ShieldAlert, Play, CheckCircle2, AlertOctagon, 
  RotateCcw, Zap, KeyRound, Lock, Server, Cpu, Database,
  ShieldCheck, AlertTriangle, UserCheck, RefreshCw, Eye, Scan
} from 'lucide-react';
import { ApiService } from '../services/api';
import { SimulationResult } from '../types';

export const Simulations: React.FC = () => {
  const [isRunning, setIsRunning] = useState(false);
  const [activeSimulation, setActiveSimulation] = useState<string | null>(null);
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [resetMsg, setResetMsg] = useState<string | null>(null);
  const [currentUser, setCurrentUser] = useState<any>(null);
  const [authMsg, setAuthMsg] = useState<string | null>(null);

  // Load auth state
  const checkAuth = () => {
    const user = ApiService.getCurrentUser();
    setCurrentUser(user);
  };

  useEffect(() => {
    checkAuth();
  }, []);

  // Quick Admin Authorization
  const handleAuthorizeAdmin = async () => {
    try {
      const res = await ApiService.loginStaff('admin', 'Admin@1234');
      ApiService.setAuth(res.access_token, { username: res.username, role: res.role });
      setCurrentUser({ username: res.username, role: res.role });
      setAuthMsg('Authorized as SUPER_ADMIN! Full simulation execution permissions armed.');
      setTimeout(() => setAuthMsg(null), 4000);
    } catch (err: any) {
      alert(`Admin Authorization failed: ${err.message}`);
    }
  };

  const simulationScenarios = [
    {
      id: 'BRUTE_FORCE',
      title: 'Brute Force PIN Attack',
      desc: 'Injects sequential invalid PINs to trigger threat detector, automated card lockout, and incident creation.',
      category: 'AUTH',
      icon: KeyRound,
      color: 'border-amber-500/40 hover:border-amber-400',
    },
    {
      id: 'ATM_TAMPER',
      title: 'ATM Hardware Tamper Alarm',
      desc: 'Simulates physical chassis breach on hardware microswitch sensor, forcing terminal into emergency lockdown.',
      category: 'ATM',
      icon: Cpu,
      color: 'border-orange-500/40 hover:border-orange-400',
    },
    {
      id: 'FIRMWARE_TAMPER',
      title: 'Firmware Manifest Integrity Failure',
      desc: 'Injects unverified firmware manifest signature, failing Ed25519 cryptographic check and locking ATM.',
      category: 'ATM',
      icon: Lock,
      color: 'border-amber-500/40 hover:border-amber-400',
    },
    {
      id: 'CERTIFICATE_FAILURE',
      title: 'Revoked / Expired mTLS Certificate',
      desc: 'Simulates connection with revoked X.509 device certificate, failing mutual TLS identity verification.',
      category: 'ATM',
      icon: ShieldAlert,
      color: 'border-orange-500/40 hover:border-orange-400',
    },
    {
      id: 'SUSPICIOUS_TXN',
      title: 'Suspicious High-Risk Withdrawal',
      desc: 'Executes high-value anomaly withdrawal in foreign city with untrusted device to exercise Risk Engine.',
      category: 'TRANSACTION',
      icon: Zap,
      color: 'border-amber-500/40 hover:border-amber-400',
    },
    {
      id: 'DUPLICATE_TXN',
      title: 'Replay / Duplicate Transaction Attack',
      desc: 'Replays an exact transaction with reused nonce and MAC to test idempotency and replay guards.',
      category: 'TRANSACTION',
      icon: Database,
      color: 'border-amber-500/40 hover:border-amber-400',
    },
    {
      id: 'IMPOSSIBLE_TRAVEL',
      title: 'Impossible Travel Velocity Anomaly',
      desc: 'Consecutive transactions originating from geographically distant cities within minutes (Chennai -> Delhi).',
      category: 'TRANSACTION',
      icon: Zap,
      color: 'border-amber-500/40 hover:border-amber-400',
    },
    {
      id: 'API_ABUSE',
      title: 'API Rate Limit Abuse Flood',
      desc: 'Bursts 60 requests in 3 seconds to exceed token bucket limit, returning HTTP 429 and logging security event.',
      category: 'API',
      icon: Server,
      color: 'border-amber-500/40 hover:border-amber-400',
    },
    {
      id: 'UNAUTHORIZED_ACCESS',
      title: 'Unauthorized Privilege Escalation',
      desc: 'Probes administrative security policy endpoints with forged headers to test Zero-Trust RBAC guards.',
      category: 'ADMIN',
      icon: Lock,
      color: 'border-orange-500/40 hover:border-orange-400',
    },
    {
      id: 'SESSION_ABUSE',
      title: 'Session & Refresh Token Replay',
      desc: 'Replays an already-revoked refresh token family, verifying RFC 6749 full token family invalidation.',
      category: 'AUTH',
      icon: Database,
      color: 'border-amber-500/40 hover:border-amber-400',
    },
  ];

  const handleRun = async (simId: string) => {
    setIsRunning(true);
    setActiveSimulation(simId);
    setResult(null);
    setResetMsg(null);
    try {
      // Auto ensures admin authorization
      const res = await ApiService.runSimulation(simId, 1);
      setResult(res);
      checkAuth();
    } catch (err: any) {
      alert(err.message || 'Simulation execution failed.');
    } finally {
      setIsRunning(false);
    }
  };

  const handleReset = async () => {
    setIsRunning(true);
    try {
      const res = await ApiService.resetDemo();
      setResetMsg(res.message);
      setResult(null);
    } catch (err: any) {
      alert(err.message || 'Reset failed.');
    } finally {
      setIsRunning(false);
    }
  };

  const [selectedCat, setSelectedCat] = useState<string>('ALL');

  const filteredScenarios = simulationScenarios.filter(sim => {
    if (selectedCat === 'ALL') return true;
    return sim.category === selectedCat;
  });

  return (
    <div className="min-h-[calc(100vh-4rem)] p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto space-y-8 bg-cyber-matrix">
      
      {/* ============================================================== */}
      {/* HERO SECTION MATCHING USER'S ATTACHED IMAGE (AMBER CYBER HUD) */}
      {/* ============================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center pt-2">
        
        {/* Left Column: AI Powered Security Header & Actions */}
        <div className="lg:col-span-7 space-y-6">
          
          {/* Glowing Pill Badge */}
          <div className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full bg-amber-500/10 border border-amber-500/30 text-xs font-cyber text-amber-300 shadow-[0_0_20px_rgba(245,158,11,0.2)]">
            <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping" />
            <span>🌐 Trusted by Security Teams Worldwide</span>
          </div>

          {/* Futuristic Title */}
          <div className="space-y-2">
            <h1 className="text-4xl sm:text-5xl font-black text-white font-cyber tracking-tight leading-none">
              AI POWERED <br />
              <span className="bg-gradient-to-r from-white via-zinc-200 to-zinc-400 bg-clip-text text-transparent">
                DEFENSIVE ATTACK
              </span> <br />
              <span className="bg-gradient-to-r from-amber-400 via-amber-500 to-orange-500 bg-clip-text text-transparent text-glow-amber">
                SIMULATIONS
              </span>
            </h1>
            <p className="text-zinc-400 text-sm max-w-xl font-serif-vintage leading-relaxed pt-2">
              Safe, in-app attack simulations exercising genuine detection pipelines on internal synthetic telemetry. All events traverse the unified 10-stage defensive security pipeline.
            </p>
          </div>

          {/* Admin Authorization & Launch Controls */}
          <div className="flex flex-wrap items-center gap-4 pt-2">
            <button
              onClick={() => handleRun('BRUTE_FORCE')}
              disabled={isRunning}
              className="btn-cyber-primary px-6 py-3 rounded-full text-xs font-cyber tracking-wider uppercase flex items-center space-x-2"
            >
              <Play className="w-4 h-4 fill-black" />
              <span>START MONITORING</span>
            </button>

            <button
              onClick={handleAuthorizeAdmin}
              className="btn-cyber-secondary px-6 py-3 rounded-full text-xs font-cyber tracking-wider uppercase flex items-center space-x-2"
            >
              <UserCheck className="w-4 h-4 text-amber-400" />
              <span>
                {currentUser?.role === 'SUPER_ADMIN' ? 'ADMIN AUTHORIZED ✓' : 'AUTHORIZE ADMIN'}
              </span>
            </button>

            <button
              onClick={handleReset}
              disabled={isRunning}
              className="px-4 py-3 rounded-full bg-zinc-900 border border-zinc-700 text-zinc-300 hover:text-white hover:border-amber-400 text-xs font-mono transition flex items-center space-x-2"
              title="Reset locked ATMs and cards"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>RESET DEMO</span>
            </button>
          </div>

          {/* Sector Alert Banner (From Image) */}
          <div className="glass-card rounded-2xl p-4 border border-amber-500/30 flex items-center space-x-4 max-w-lg shadow-[0_0_25px_rgba(245,158,11,0.15)]">
            <div className="w-10 h-10 rounded-xl bg-amber-500/20 border border-amber-500/40 flex items-center justify-center shrink-0">
              <AlertTriangle className="w-5 h-5 text-amber-400 animate-pulse" />
            </div>
            <div>
              <div className="text-xs font-mono font-bold text-amber-300 uppercase tracking-wider">
                SECTOR C-12 TELEMETRY ARMED
              </div>
              <div className="text-[11px] text-zinc-400 font-serif-vintage">
                Automated threat detection, behavioral UEBA baselines, and instant playbook responses active.
              </div>
            </div>
          </div>

        </div>

        {/* Right Column: Biometrical Scan HUD Card (From Image) */}
        <div className="lg:col-span-5 flex justify-center">
          <div className="biometric-hud w-full max-w-md p-6 space-y-4">
            
            {/* Header */}
            <div className="flex items-center justify-between text-xs font-cyber">
              <span className="text-amber-300 font-bold uppercase tracking-wider flex items-center space-x-1.5">
                <Scan className="w-4 h-4 text-amber-400" />
                <span>Biometrical Scan</span>
              </span>
              <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 text-[10px] font-mono">
                LIVE HUD
              </span>
            </div>

            {/* Glowing Face Silhouette Box */}
            <div className="h-44 bg-black/60 rounded-xl border border-amber-500/30 flex flex-col items-center justify-center relative overflow-hidden group">
              
              {/* Corner targeting reticles */}
              <div className="absolute top-2 left-2 w-3 h-3 border-t-2 border-l-2 border-amber-400" />
              <div className="absolute top-2 right-2 w-3 h-3 border-t-2 border-r-2 border-amber-400" />
              <div className="absolute bottom-2 left-2 w-3 h-3 border-b-2 border-l-2 border-amber-400" />
              <div className="absolute bottom-2 right-2 w-3 h-3 border-b-2 border-r-2 border-amber-400" />

              {/* Face Outline SVG */}
              <svg className="w-20 h-20 text-amber-400 stroke-current" viewBox="0 0 24 24" fill="none" strokeWidth="1.2">
                <path d="M12 2a7 7 0 0 0-7 7c0 5 7 13 7 13s7-8 7-13a7 7 0 0 0-7-7z" opacity="0.3" />
                <circle cx="12" cy="9" r="4" />
                <path d="M9 19c-3 1-5 2.5-5 4h16c0-1.5-2-3-5-4" />
              </svg>

              <div className="text-center mt-2">
                <div className="text-xs font-cyber font-bold text-white">Adel Bennett</div>
                <div className="mt-1 px-2.5 py-0.5 bg-amber-500/20 border border-amber-500/40 rounded text-[10px] font-mono font-bold text-amber-300 tracking-wider">
                  WHJG-IU71-X7BA
                </div>
              </div>
            </div>

            <p className="text-xs text-zinc-400 font-serif-vintage leading-relaxed">
              AI-powered surveillance system with real-time behavioral detection, facial scan verification, and anomaly tracking.
            </p>
          </div>
        </div>

      </div>

      {/* Admin Authorization Status Toast */}
      {authMsg && (
        <div className="p-4 bg-amber-500/20 border border-amber-500/50 rounded-xl text-xs font-mono text-amber-200 flex items-center space-x-2">
          <CheckCircle2 className="w-5 h-5 text-amber-400" />
          <span>{authMsg}</span>
        </div>
      )}

      {/* Reset Feedback */}
      {resetMsg && (
        <div className="p-4 rounded-xl bg-zinc-900 border border-amber-500/40 text-amber-300 font-mono text-xs flex items-center space-x-2">
          <CheckCircle2 className="w-4 h-4 text-amber-400" />
          <span>{resetMsg}</span>
        </div>
      )}

      {/* ============================================================== */}
      {/* SIMULATION RESULT HUD CONSOLE */}
      {/* ============================================================== */}
      {result && (
        <div className="cyber-card p-6 rounded-2xl border-2 border-amber-500/50 space-y-4 shadow-[0_0_35px_rgba(245,158,11,0.2)]">
          <div className="flex items-center justify-between border-b border-amber-500/20 pb-3">
            <div className="flex items-center space-x-3">
              <span className="w-3 h-3 rounded-full bg-amber-400 animate-ping" />
              <h2 className="text-sm font-bold font-cyber text-white uppercase tracking-wider">
                SIMULATION RESULT: {result.simulation_type}
              </h2>
            </div>
            <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
              SIMULATION ID: #{result.simulation_id}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
            <div className="p-3 rounded-xl bg-black/60 border border-zinc-800">
              <div className="text-[10px] text-zinc-500 uppercase">Detection Status</div>
              <div className="font-bold text-amber-300 mt-1">{result.threat_detected ? '✓ THREAT DETECTED' : '✗ PASSED'}</div>
            </div>
            <div className="p-3 rounded-xl bg-black/60 border border-zinc-800">
              <div className="text-[10px] text-zinc-500 uppercase">Detection Rule</div>
              <div className="font-bold text-white mt-1">{result.detection_rule || 'RULE-SV-001'}</div>
            </div>
            <div className="p-3 rounded-xl bg-black/60 border border-zinc-800">
              <div className="text-[10px] text-zinc-500 uppercase">Incident Created</div>
              <div className="font-bold text-amber-400 mt-1">{result.incident_code || 'SV-INC-RECORDED'}</div>
            </div>
          </div>

          {/* Triggered Actions */}
          {result.actions_triggered && result.actions_triggered.length > 0 && (
            <div className="space-y-2 pt-2">
              <span className="text-[11px] font-mono text-amber-400 uppercase tracking-wider block font-bold">
                SOAR PLAYBOOK ACTIONS AUTOMATICALLY ENFORCED:
              </span>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                {result.actions_triggered.map((act: string, i: number) => (
                  <div key={i} className="flex items-center space-x-2 text-xs font-mono text-zinc-200 bg-zinc-950 p-2.5 rounded border border-zinc-800">
                    <CheckCircle2 className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                    <span>{act}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 10-Stage Pipeline Trace */}
          {result.steps && result.steps.length > 0 && (
            <div className="space-y-2 pt-2 border-t border-zinc-800/80">
              <span className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider block">
                UNIFIED 10-STAGE PIPELINE EXECUTION TRACE:
              </span>
              <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                {result.steps.map((st: any, i: number) => (
                  <div key={i} className="flex items-center justify-between text-[11px] font-mono bg-black/40 p-2 rounded border border-zinc-800/60">
                    <div className="flex items-center space-x-2">
                      <span className="text-amber-400 font-bold">{i + 1}. {st.step}</span>
                      <span className="text-zinc-400">• {st.detail}</span>
                    </div>
                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/10 text-amber-300 border border-amber-500/20">
                      {st.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ============================================================== */}
      {/* SCENARIO FILTER PILLS & GRID OF 10 ATTACK SIMULATIONS */}
      {/* ============================================================== */}
      <div className="space-y-4">
        
        {/* Category Filter Pills */}
        <div className="flex flex-wrap gap-2">
          {['ALL', 'AUTH', 'ATM', 'TRANSACTION', 'API', 'ADMIN'].map(cat => (
            <button
              key={cat}
              onClick={() => setSelectedCat(cat)}
              className={`px-4 py-2 rounded-full text-xs font-cyber tracking-wider transition uppercase ${
                selectedCat === cat
                  ? 'btn-cyber-primary shadow-[0_0_15px_rgba(245,158,11,0.4)]'
                  : 'bg-zinc-900 text-zinc-400 hover:text-white border border-zinc-800'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>

        {/* 10 Attack Simulations Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredScenarios.map(scenario => {
            const Icon = scenario.icon;
            const isCurrent = isRunning && activeSimulation === scenario.id;

            return (
              <div
                key={scenario.id}
                className={`glass-card p-6 rounded-2xl border transition group flex flex-col justify-between hover:border-amber-500/50 hover:shadow-[0_0_25px_rgba(245,158,11,0.15)]`}
              >
                <div className="space-y-4">
                  <div className="flex items-start justify-between">
                    <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 group-hover:scale-110 transition">
                      <Icon className="w-5 h-5" />
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-zinc-900 text-amber-300 border border-zinc-800">
                      {scenario.category}
                    </span>
                  </div>

                  <div>
                    <h3 className="text-base font-bold text-white font-cyber group-hover:text-amber-300 transition">
                      {scenario.title}
                    </h3>
                    <p className="text-xs text-zinc-400 font-serif-vintage mt-1 leading-relaxed">
                      {scenario.desc}
                    </p>
                  </div>
                </div>

                <div className="mt-6 pt-4 border-t border-zinc-800 flex items-center justify-between">
                  <span className="text-[10px] font-mono text-zinc-500">
                    CODE: {scenario.id}
                  </span>
                  <button
                    onClick={() => handleRun(scenario.id)}
                    disabled={isRunning}
                    className="btn-cyber-primary px-4 py-2 rounded-lg text-xs font-cyber tracking-wider flex items-center space-x-1.5"
                  >
                    {isCurrent ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        <span>RUNNING...</span>
                      </>
                    ) : (
                      <>
                        <Play className="w-3.5 h-3.5 fill-black" />
                        <span>EXECUTE</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            );
          })}
        </div>

      </div>

    </div>
  );
};
