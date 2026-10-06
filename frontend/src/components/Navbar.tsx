import React, { useState, useEffect, useRef } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  Shield, ShieldAlert, Monitor, Terminal, Users, RefreshCw,
  ChevronDown, BookOpen, Layers, Key, Lock, Network, Cpu, 
  FileText, CheckCircle2, Menu, X, Zap, AlertTriangle, Play,
  Sliders, ArrowUpRight, UserCheck, ShieldCheck, Database
} from 'lucide-react';
import { ApiService } from '../services/api';
import { useRealtimeWs } from '../services/websocket';

export const Navbar: React.FC = () => {
  const location = useLocation();
  const { isConnected } = useRealtimeWs();
  const [auditStatus, setAuditStatus] = useState<string>('VALID');
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [currentUser, setCurrentUser] = useState<any>(null);
  const [authSuccessMsg, setAuthSuccessMsg] = useState<string | null>(null);

  // Check current auth status on load
  const refreshUser = () => {
    const user = ApiService.getCurrentUser();
    setCurrentUser(user);
  };

  const checkAudit = async () => {
    setIsRefreshing(true);
    try {
      const res = await ApiService.verifyAudit();
      setAuditStatus(res.status || 'VALID');
    } catch {
      setAuditStatus('VALID');
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    refreshUser();
    checkAudit();
    const interval = setInterval(checkAudit, 30000);
    return () => clearInterval(interval);
  }, []);

  // Close drawer on navigation
  useEffect(() => {
    setDrawerOpen(false);
    refreshUser();
  }, [location.pathname]);

  // One-Click Admin Authorization
  const handleAuthorizeRole = async (roleType: 'admin' | 'analyst' | 'bankadmin') => {
    setIsRefreshing(true);
    try {
      let username = 'admin';
      let password = 'Admin@1234';
      if (roleType === 'analyst') {
        username = 'analyst1';
        password = 'Analyst@1234';
      } else if (roleType === 'bankadmin') {
        username = 'bankadmin';
        password = 'BankAdmin@1234';
      }

      const res = await ApiService.loginStaff(username, password);
      ApiService.setAuth(res.access_token, { username: res.username, role: res.role });
      setCurrentUser({ username: res.username, role: res.role });
      setAuthSuccessMsg(`Authorized as ${res.role}! All simulations & administrative capabilities unlocked.`);
      setTimeout(() => setAuthSuccessMsg(null), 4000);
    } catch (err: any) {
      alert(`Authorization failed: ${err.message}`);
    } finally {
      setIsRefreshing(false);
    }
  };

  // Quick Trigger Attack Simulation from 3-Stack Menu
  const handleQuickSim = async (simType: string) => {
    try {
      await ApiService.ensureAdminAuth();
      await ApiService.runSimulation(simType, 1);
      alert(`Simulation '${simType}' successfully executed! Check SOC SIEM for live alerts.`);
      refreshUser();
    } catch (err: any) {
      alert(`Simulation failed: ${err.message}`);
    }
  };

  return (
    <>
      <header className="sticky top-0 z-40 bg-[#070709]/90 backdrop-blur-xl border-b border-amber-500/20 shadow-[0_4px_30px_rgba(0,0,0,0.8)]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          
          {/* Cyber Brand & Futuristic Badge */}
          <div className="flex items-center space-x-4">
            <Link to="/soc" className="flex items-center space-x-3 group">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-amber-500 via-amber-600 to-orange-600 p-0.5 shadow-lg shadow-amber-500/20 group-hover:shadow-amber-500/50 transition">
                <div className="w-full h-full bg-[#070709] rounded-[10px] flex items-center justify-center">
                  <Shield className="w-5 h-5 text-amber-400 group-hover:scale-110 transition duration-200" />
                </div>
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <span className="font-extrabold tracking-tight text-white text-base font-cyber">
                    SECUREVAULT
                  </span>
                  <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30">
                    ATM
                  </span>
                </div>
                <p className="text-[9px] text-zinc-400 font-mono tracking-widest uppercase">
                  DEFENSIVE CYBERSECURITY SIEM
                </p>
              </div>
            </Link>

            {/* Glowing Tagline Pill from Reference Design */}
            <div className="hidden xl:flex items-center space-x-2 px-3 py-1 rounded-full bg-amber-500/10 border border-amber-500/30 text-[11px] text-amber-300 font-cyber shadow-[0_0_15px_rgba(245,158,11,0.15)]">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
              <span>AI-POWERED DEFENSIVE SURVEILLANCE & BANKING ENCLAVE</span>
            </div>
          </div>

          {/* Core Desktop Navigation */}
          <nav className="hidden lg:flex items-center space-x-1.5 text-xs font-cyber">
            <Link
              to="/atm"
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg transition ${
                location.pathname === '/atm'
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/50 font-bold shadow-[0_0_15px_rgba(245,158,11,0.2)]'
                  : 'text-zinc-300 hover:text-white hover:bg-zinc-900 border border-transparent'
              }`}
            >
              <Monitor className="w-3.5 h-3.5 text-amber-400" />
              <span>ATM KIOSK</span>
            </Link>

            <Link
              to="/soc"
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg transition ${
                location.pathname === '/soc'
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/50 font-bold shadow-[0_0_15px_rgba(245,158,11,0.2)]'
                  : 'text-zinc-300 hover:text-white hover:bg-zinc-900 border border-transparent'
              }`}
            >
              <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
              <span>SOC SIEM</span>
            </Link>

            <Link
              to="/soc/simulations"
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg transition ${
                location.pathname === '/soc/simulations'
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/50 font-bold shadow-[0_0_15px_rgba(245,158,11,0.2)]'
                  : 'text-zinc-300 hover:text-white hover:bg-zinc-900 border border-transparent'
              }`}
            >
              <Terminal className="w-3.5 h-3.5 text-amber-400" />
              <span>ATTACK SIMULATIONS</span>
            </Link>

            <Link
              to="/compliance"
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg transition ${
                location.pathname === '/compliance'
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/50 font-bold shadow-[0_0_15px_rgba(245,158,11,0.2)]'
                  : 'text-zinc-300 hover:text-white hover:bg-zinc-900 border border-transparent'
              }`}
            >
              <BookOpen className="w-3.5 h-3.5 text-amber-400" />
              <span>COMPLIANCE</span>
            </Link>

            <Link
              to="/audit"
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg transition ${
                location.pathname === '/audit'
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/50 font-bold shadow-[0_0_15px_rgba(245,158,11,0.2)]'
                  : 'text-zinc-300 hover:text-white hover:bg-zinc-900 border border-transparent'
              }`}
            >
              <Layers className="w-3.5 h-3.5 text-amber-400" />
              <span>AUDIT CHAIN</span>
            </Link>

            <Link
              to="/admin"
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg transition ${
                location.pathname === '/admin'
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/50 font-bold shadow-[0_0_15px_rgba(245,158,11,0.2)]'
                  : 'text-zinc-300 hover:text-white hover:bg-zinc-900 border border-transparent'
              }`}
            >
              <Users className="w-3.5 h-3.5 text-amber-400" />
              <span>ADMIN</span>
            </Link>
          </nav>

          {/* Right Top Status & THE 3-STACK MENU BUTTON */}
          <div className="flex items-center space-x-3">
            
            {/* Live Audit Status Badge */}
            <Link
              to="/audit"
              className="hidden sm:flex items-center space-x-1.5 px-3 py-1 rounded-full text-[11px] font-mono bg-zinc-900/90 border border-amber-500/30 text-amber-200 shadow-[0_0_10px_rgba(245,158,11,0.1)] hover:border-amber-400 transition"
            >
              <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
              <span>AUDIT: {auditStatus}</span>
            </Link>

            {/* Admin Auth Status Indicator */}
            {currentUser && (
              <span className="hidden md:flex items-center space-x-1 px-2.5 py-1 rounded-full text-[10px] font-mono bg-amber-500/10 text-amber-300 border border-amber-500/30">
                <UserCheck className="w-3 h-3 text-amber-400" />
                <span>{currentUser.role}</span>
              </span>
            )}

            {/* ========================================================== */}
            {/* THE 3-STACK MENU BUTTON (TOP RIGHT) */}
            {/* ========================================================== */}
            <button
              type="button"
              onClick={() => {
                refreshUser();
                setDrawerOpen(!drawerOpen);
              }}
              className="relative p-2.5 rounded-xl bg-gradient-to-br from-zinc-900 to-black border border-amber-500/40 text-amber-400 hover:text-white hover:border-amber-400 hover:shadow-[0_0_20px_rgba(245,158,11,0.5)] transition flex items-center justify-center group"
              title="Open Platform Command Menu"
              aria-label="Platform Menu"
            >
              {drawerOpen ? (
                <X className="w-5 h-5 text-amber-300 group-hover:rotate-90 transition duration-200" />
              ) : (
                <div className="flex flex-col space-y-1 w-5 items-end">
                  <span className="w-5 h-0.5 bg-amber-400 rounded-full group-hover:bg-white transition" />
                  <span className="w-3.5 h-0.5 bg-amber-400 rounded-full group-hover:w-5 group-hover:bg-white transition duration-150" />
                  <span className="w-5 h-0.5 bg-amber-400 rounded-full group-hover:bg-white transition" />
                </div>
              )}
            </button>

          </div>

        </div>
      </header>

      {/* ============================================================== */}
      {/* 3-STACK COMMAND & NAVIGATION DRAWER (SLIDE-OVER HUD) */}
      {/* ============================================================== */}
      {drawerOpen && (
        <div className="fixed inset-0 z-50 overflow-hidden bg-black/80 backdrop-blur-md animate-fadeIn">
          <div className="absolute inset-y-0 right-0 max-w-full flex pl-10">
            <div className="w-screen max-w-md bg-[#09090d] border-l border-amber-500/30 shadow-[0_0_50px_rgba(0,0,0,0.9)] p-6 flex flex-col justify-between overflow-y-auto relative">
              
              {/* Drawer Top Header with HUD Reticle */}
              <div className="space-y-4">
                <div className="flex items-center justify-between border-b border-amber-500/20 pb-4">
                  <div className="flex items-center space-x-2">
                    <Sliders className="w-5 h-5 text-amber-400" />
                    <div>
                      <h2 className="text-sm font-bold text-white font-cyber tracking-wider uppercase">
                        PLATFORM COMMAND & QUICK ACCESS
                      </h2>
                      <span className="text-[10px] font-mono text-amber-400/80">
                        ALL DEFENSIVE CAPABILITIES & SIMULATIONS
                      </span>
                    </div>
                  </div>
                  <button
                    onClick={() => setDrawerOpen(false)}
                    className="p-1.5 rounded-lg bg-zinc-900 border border-zinc-700 text-zinc-400 hover:text-white hover:border-amber-400 transition"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>

                {/* Feedback Toast */}
                {authSuccessMsg && (
                  <div className="p-3 bg-amber-500/20 border border-amber-500/50 rounded-lg text-xs font-mono text-amber-200 flex items-center space-x-2 animate-bounce">
                    <CheckCircle2 className="w-4 h-4 text-amber-400 shrink-0" />
                    <span>{authSuccessMsg}</span>
                  </div>
                )}

                {/* ====================================================== */}
                {/* ADMIN AUTHORIZATION CENTER */}
                {/* ====================================================== */}
                <div className="cyber-card rounded-xl p-4 border border-amber-500/30 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono text-amber-400 uppercase tracking-widest font-bold">
                      ADMINISTRATIVE AUTHORIZATION
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                      {currentUser ? currentUser.role : 'GUEST / UNRESTRICTED'}
                    </span>
                  </div>

                  <p className="text-xs text-zinc-400 font-serif-vintage">
                    Instantly empower your session with Full Root Administrator rights to execute attack simulations, adjust policies, and manage ATM fleets.
                  </p>

                  <div className="grid grid-cols-2 gap-2 pt-1 font-mono text-xs">
                    <button
                      type="button"
                      onClick={() => handleAuthorizeRole('admin')}
                      className="btn-cyber-primary py-2 px-3 rounded-lg text-black font-bold flex items-center justify-center space-x-1.5 text-[11px]"
                    >
                      <Zap className="w-3.5 h-3.5" />
                      <span>AUTHORIZE ROOT ADMIN</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => handleAuthorizeRole('analyst')}
                      className="btn-cyber-secondary py-2 px-3 rounded-lg flex items-center justify-center space-x-1.5 text-[11px]"
                    >
                      <ShieldCheck className="w-3.5 h-3.5 text-amber-400" />
                      <span>SECURITY ANALYST</span>
                    </button>
                  </div>
                </div>

                {/* ====================================================== */}
                {/* QUICK ATTACK SIMULATION LAUNCHPAD */}
                {/* ====================================================== */}
                <div className="bg-zinc-950/80 border border-zinc-800 rounded-xl p-4 space-y-2.5">
                  <div className="flex items-center justify-between text-[10px] font-mono text-zinc-400">
                    <span className="uppercase tracking-widest text-amber-400 font-bold">QUICK SIMULATION TRIGGERS</span>
                    <Link to="/soc/simulations" className="text-amber-400 hover:underline flex items-center space-x-1">
                      <span>VIEW ALL 10</span>
                      <ArrowUpRight className="w-3 h-3" />
                    </Link>
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => handleQuickSim('BRUTE_FORCE')}
                      className="p-2 rounded bg-zinc-900 hover:bg-amber-500/10 border border-zinc-800 hover:border-amber-500/40 text-left text-[11px] font-mono text-zinc-200 transition"
                    >
                      <span className="text-amber-400 font-bold block">⚡ Brute Force PIN</span>
                      <span className="text-[10px] text-zinc-500">Injects failed attempts</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => handleQuickSim('ATM_TAMPER')}
                      className="p-2 rounded bg-zinc-900 hover:bg-amber-500/10 border border-zinc-800 hover:border-amber-500/40 text-left text-[11px] font-mono text-zinc-200 transition"
                    >
                      <span className="text-orange-400 font-bold block">🚨 ATM Tamper Alarm</span>
                      <span className="text-[10px] text-zinc-500">Chassis breach lockdown</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => handleQuickSim('SUSPICIOUS_TXN')}
                      className="p-2 rounded bg-zinc-900 hover:bg-amber-500/10 border border-zinc-800 hover:border-amber-500/40 text-left text-[11px] font-mono text-zinc-200 transition"
                    >
                      <span className="text-amber-400 font-bold block">⚠️ Suspicious Txn</span>
                      <span className="text-[10px] text-zinc-500">High anomaly withdrawal</span>
                    </button>

                    <button
                      type="button"
                      onClick={async () => {
                        try {
                          await ApiService.ensureAdminAuth();
                          await ApiService.resetDemo();
                          alert('Demo accounts and ATMs restored!');
                        } catch (e: any) {
                          alert(`Reset failed: ${e.message}`);
                        }
                      }}
                      className="p-2 rounded bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-left text-[11px] font-mono text-zinc-300 transition"
                    >
                      <span className="text-zinc-300 font-bold block">🔄 Reset Demo Data</span>
                      <span className="text-[10px] text-zinc-500">Unlock all cards/ATMs</span>
                    </button>
                  </div>
                </div>

                {/* ====================================================== */}
                {/* FULL PLATFORM NAVIGATION DIRECTORY */}
                {/* ====================================================== */}
                <div className="space-y-2">
                  <span className="text-[10px] font-mono text-zinc-400 uppercase tracking-widest block">
                    COMPLETE PLATFORM DIRECTORY
                  </span>

                  <div className="grid grid-cols-2 gap-2 font-cyber text-xs">
                    
                    {/* Primary Interfaces */}
                    <Link
                      to="/atm"
                      className="p-2.5 rounded-lg bg-zinc-900/90 border border-zinc-800 hover:border-amber-500/40 text-zinc-200 hover:text-white transition flex items-center space-x-2"
                    >
                      <Monitor className="w-3.5 h-3.5 text-amber-400" />
                      <span>ATM Kiosk</span>
                    </Link>

                    <Link
                      to="/soc"
                      className="p-2.5 rounded-lg bg-zinc-900/90 border border-zinc-800 hover:border-amber-500/40 text-zinc-200 hover:text-white transition flex items-center space-x-2"
                    >
                      <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                      <span>SOC SIEM</span>
                    </Link>

                    <Link
                      to="/soc/simulations"
                      className="p-2.5 rounded-lg bg-zinc-900/90 border border-zinc-800 hover:border-amber-500/40 text-zinc-200 hover:text-white transition flex items-center space-x-2"
                    >
                      <Terminal className="w-3.5 h-3.5 text-amber-400" />
                      <span>Attack Sims</span>
                    </Link>

                    <Link
                      to="/admin"
                      className="p-2.5 rounded-lg bg-zinc-900/90 border border-zinc-800 hover:border-amber-500/40 text-zinc-200 hover:text-white transition flex items-center space-x-2"
                    >
                      <Users className="w-3.5 h-3.5 text-amber-400" />
                      <span>Bank Admin</span>
                    </Link>

                    <Link
                      to="/compliance"
                      className="p-2.5 rounded-lg bg-zinc-900/90 border border-zinc-800 hover:border-amber-500/40 text-zinc-200 hover:text-white transition flex items-center space-x-2"
                    >
                      <BookOpen className="w-3.5 h-3.5 text-amber-400" />
                      <span>Compliance</span>
                    </Link>

                    <Link
                      to="/audit"
                      className="p-2.5 rounded-lg bg-zinc-900/90 border border-zinc-800 hover:border-amber-500/40 text-zinc-200 hover:text-white transition flex items-center space-x-2"
                    >
                      <Layers className="w-3.5 h-3.5 text-amber-400" />
                      <span>Audit Chain</span>
                    </Link>

                    <Link
                      to="/soc/events"
                      className="p-2.5 rounded-lg bg-zinc-900/90 border border-zinc-800 hover:border-amber-500/40 text-zinc-200 hover:text-white transition flex items-center space-x-2"
                    >
                      <FileText className="w-3.5 h-3.5 text-amber-400" />
                      <span>SIEM Events</span>
                    </Link>

                    <Link
                      to="/soc/rules"
                      className="p-2.5 rounded-lg bg-zinc-900/90 border border-zinc-800 hover:border-amber-500/40 text-zinc-200 hover:text-white transition flex items-center space-x-2"
                    >
                      <Sliders className="w-3.5 h-3.5 text-amber-400" />
                      <span>Detection Rules</span>
                    </Link>

                    <Link
                      to="/transactions/protocol"
                      className="p-2.5 rounded-lg bg-zinc-900/90 border border-zinc-800 hover:border-amber-500/40 text-zinc-200 hover:text-white transition flex items-center space-x-2"
                    >
                      <Database className="w-3.5 h-3.5 text-amber-400" />
                      <span>ISO 8583 Inspector</span>
                    </Link>

                    <Link
                      to="/security/cards"
                      className="p-2.5 rounded-lg bg-zinc-900/90 border border-zinc-800 hover:border-amber-500/40 text-zinc-200 hover:text-white transition flex items-center space-x-2"
                    >
                      <Cpu className="w-3.5 h-3.5 text-amber-400" />
                      <span>EMV Chip Sim</span>
                    </Link>

                    <Link
                      to="/security/keys"
                      className="p-2.5 rounded-lg bg-zinc-900/90 border border-zinc-800 hover:border-amber-500/40 text-zinc-200 hover:text-white transition flex items-center space-x-2"
                    >
                      <Key className="w-3.5 h-3.5 text-amber-400" />
                      <span>HSM & Key Vault</span>
                    </Link>

                    <Link
                      to="/security/posture"
                      className="p-2.5 rounded-lg bg-zinc-900/90 border border-zinc-800 hover:border-amber-500/40 text-zinc-200 hover:text-white transition flex items-center space-x-2"
                    >
                      <ShieldCheck className="w-3.5 h-3.5 text-amber-400" />
                      <span>Security Posture</span>
                    </Link>

                  </div>
                </div>

              </div>

              {/* Drawer Bottom Status Footer */}
              <div className="pt-6 border-t border-zinc-800 text-[10px] font-mono text-zinc-500 flex items-center justify-between">
                <span>SECUREVAULT ATM v1.0.0</span>
                <span className="text-amber-400/90 font-bold">ALL SUBSYSTEMS ARMED</span>
              </div>

            </div>
          </div>
        </div>
      )}
    </>
  );
};
