import React, { useState, useEffect } from 'react';
import { 
  Users, Sliders, Banknote, Database, ShieldAlert, Lock, Unlock, 
  RefreshCw, CheckCircle2, Edit3, Save, X 
} from 'lucide-react';
import { ApiService } from '../services/api';
import { Atm } from '../types';

export const AdminPortal: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'CUSTOMERS' | 'POLICIES' | 'CASH_LOAD' | 'MONGODB'>('CUSTOMERS');
  const [mongoInfo, setMongoInfo] = useState<any>(null);
  const [isSyncingMongo, setIsSyncingMongo] = useState(false);
  const [mongoSyncMsg, setMongoSyncMsg] = useState<string | null>(null);
  const [customers, setCustomers] = useState<any[]>([]);
  const [policies, setPolicies] = useState<any[]>([]);
  const [atms, setAtms] = useState<Atm[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  // Policy editing
  const [editingKey, setEditingKey] = useState<string | null>(null);
  const [editJson, setEditJson] = useState<string>('');
  const [policySaveMsg, setPolicySaveMsg] = useState<string | null>(null);

  // Cash Loading state
  const [loadAtmId, setLoadAtmId] = useState<number>(1);
  const [notesToLoad, setNotesToLoad] = useState<Record<number, number>>({ 100: 500, 200: 500, 500: 1000, 2000: 200 });
  const [cashLoadSuccess, setCashLoadSuccess] = useState<string | null>(null);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [custRes, polRes, atmRes] = await Promise.all([
        ApiService.getCustomers().catch(() => []),
        ApiService.getPolicies().catch(() => []),
        ApiService.getAtms().catch(() => []),
      ]);
      setCustomers(custRes);
      setPolicies(polRes);
      setAtms(atmRes);
      const mInfo = await ApiService.getMongoStatus().catch(() => null);
      if (mInfo) setMongoInfo(mInfo);
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    ApiService.ensureAdminAuth().then(() => loadData());
  }, []);

  const handleToggleCustomerLock = async (custId: number) => {
    try {
      await ApiService.toggleCustomerLock(custId);
      loadData();
    } catch (err: any) {
      alert(err.message || 'Failed to toggle lock.');
    }
  };

  const handleStartEditPolicy = (key: string, value: any) => {
    setEditingKey(key);
    setEditJson(JSON.stringify(value, null, 2));
    setPolicySaveMsg(null);
  };

  const handleSavePolicy = async (key: string) => {
    try {
      const parsed = JSON.parse(editJson);
      await ApiService.updatePolicy(key, parsed);
      setPolicySaveMsg(`Policy '${key}' updated and cryptographically audited!`);
      setEditingKey(null);
      loadData();
    } catch (err: any) {
      alert(`Invalid JSON or error: ${err.message}`);
    }
  };

  const handleExecuteCashLoad = async () => {
    try {
      const res = await ApiService.loadCash(loadAtmId, notesToLoad);
      setCashLoadSuccess(`Successfully loaded notes to ${res.atm_code}! New total: INR ${res.cash_total?.toLocaleString('en-IN')}`);
      loadData();
    } catch (err: any) {
      alert(err.message || 'Cash load failed.');
    }
  };

  return (
    <div className="min-h-[calc(100vh-4rem)] p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="glass-panel p-4 rounded-2xl flex flex-wrap items-center justify-between gap-4 border-slate-800">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
            <Users className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-base font-bold text-white flex items-center gap-2">
              Bank Administration & Policy Console
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
                AUDITED RBAC
              </span>
            </h1>
            <p className="text-xs text-slate-400">Manage customers, adjust dynamic risk weights, and replenish ATM cash</p>
          </div>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center space-x-1 bg-slate-900/80 p-1 rounded-xl border border-slate-800">
          {[
            { id: 'CUSTOMERS', name: 'Customers & Cards', icon: Users },
            { id: 'POLICIES', name: 'Dynamic Policies', icon: Sliders },
            { id: 'CASH_LOAD', name: 'Cash Replenishment', icon: Banknote },
          ].map(tab => {
            const Icon = tab.icon;
            const active = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                  active ? 'bg-blue-600 text-white shadow' : 'text-slate-400 hover:text-white'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.name}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* TAB 1: CUSTOMERS TABLE */}
      {activeTab === 'CUSTOMERS' && (
        <div className="glass-panel rounded-3xl p-6 border-slate-800 space-y-4">
          <div className="flex justify-between items-center">
            <h2 className="text-sm font-bold text-white font-mono">REGISTERED CUSTOMER ACCOUNTS ({customers.length})</h2>
            <button onClick={loadData} className="text-xs font-mono text-slate-400 hover:text-white flex items-center gap-1">
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} /> Refresh
            </button>
          </div>

          <div className="overflow-x-auto rounded-2xl border border-slate-800">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                <tr>
                  <th className="p-3.5">Customer Name</th>
                  <th className="p-3.5">Home City</th>
                  <th className="p-3.5">Account #</th>
                  <th className="p-3.5">Balance</th>
                  <th className="p-3.5">Linked Card</th>
                  <th className="p-3.5">Status</th>
                  <th className="p-3.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-900 bg-slate-950/40">
                {customers.map((c) => {
                  const acc = c.accounts[0];
                  const card = acc?.cards[0];
                  return (
                    <tr key={c.id} className="hover:bg-slate-900/60 transition">
                      <td className="p-3.5 font-bold text-white">{c.full_name}</td>
                      <td className="p-3.5 text-slate-300">{c.home_city}</td>
                      <td className="p-3.5 text-slate-400">{acc?.account_number || 'N/A'}</td>
                      <td className="p-3.5 text-emerald-400 font-bold">
                        INR {acc?.balance ? Number(acc.balance).toLocaleString('en-IN') : '0'}
                      </td>
                      <td className="p-3.5 text-cyan-400">
                        {card ? `•••• ${card.last4} (${card.status})` : 'None'}
                      </td>
                      <td className="p-3.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          c.locked ? 'bg-rose-500/20 text-rose-400' : 'bg-emerald-500/20 text-emerald-400'
                        }`}>
                          {c.locked ? 'LOCKED' : 'ACTIVE'}
                        </span>
                      </td>
                      <td className="p-3.5 text-right">
                        <button
                          onClick={() => handleToggleCustomerLock(c.id)}
                          className={`px-3 py-1 rounded-lg text-[10px] font-bold transition flex items-center gap-1.5 ml-auto ${
                            c.locked
                              ? 'bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 border border-emerald-500/40'
                              : 'bg-rose-600/20 hover:bg-rose-600/30 text-rose-400 border border-rose-500/40'
                          }`}
                        >
                          {c.locked ? <Unlock className="w-3 h-3" /> : <Lock className="w-3 h-3" />}
                          <span>{c.locked ? 'Unlock Account' : 'Lock Account'}</span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: POLICIES */}
      {activeTab === 'POLICIES' && (
        <div className="glass-panel rounded-3xl p-6 border-slate-800 space-y-6">
          <div className="flex justify-between items-center">
            <div>
              <h2 className="text-sm font-bold text-white font-mono">DYNAMIC SECURITY POLICIES & THRESHOLDS</h2>
              <p className="text-xs text-slate-400">Policies update live without restarting application server</p>
            </div>
            {policySaveMsg && (
              <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-3 py-1 rounded-lg border border-emerald-500/20">
                {policySaveMsg}
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {policies.map(pol => {
              const isEditing = editingKey === pol.key;
              return (
                <div key={pol.id} className="bg-slate-950 p-5 rounded-2xl border border-slate-800 space-y-3">
                  <div className="flex justify-between items-start">
                    <div>
                      <h3 className="text-xs font-mono font-bold text-blue-400">{pol.key}</h3>
                      <p className="text-[11px] text-slate-400">{pol.description}</p>
                    </div>
                    {!isEditing && (
                      <button
                        onClick={() => handleStartEditPolicy(pol.key, pol.value)}
                        className="text-xs text-slate-400 hover:text-white p-1"
                      >
                        <Edit3 className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>

                  {isEditing ? (
                    <div className="space-y-3">
                      <textarea
                        rows={6}
                        value={editJson}
                        onChange={e => setEditJson(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-700 rounded-xl p-3 font-mono text-xs text-slate-200 focus:outline-none focus:border-blue-500"
                      />
                      <div className="flex gap-2">
                        <button
                          onClick={() => handleSavePolicy(pol.key)}
                          className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-bold font-mono flex items-center gap-1.5"
                        >
                          <Save className="w-3.5 h-3.5" />
                          <span>Save & Audit</span>
                        </button>
                        <button
                          onClick={() => setEditingKey(null)}
                          className="px-3 py-1.5 bg-slate-800 text-slate-400 hover:text-white rounded-lg text-xs font-mono"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  ) : (
                    <pre className="bg-slate-900/60 p-3 rounded-xl border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto">
                      {JSON.stringify(pol.value, null, 2)}
                    </pre>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* TAB 3: CASH REPLENISHMENT */}
      {activeTab === 'CASH_LOAD' && (
        <div className="glass-panel rounded-3xl p-6 border-slate-800 max-w-xl mx-auto space-y-6">
          <div className="text-center space-y-1">
            <h2 className="text-base font-bold text-white font-mono">ATM Cash Replenishment Console</h2>
            <p className="text-xs text-slate-400">Operator loading updates hardware inventory and logs audit record</p>
          </div>

          {cashLoadSuccess && (
            <div className="p-3 bg-emerald-950/60 border border-emerald-500/40 rounded-xl text-emerald-300 text-xs font-mono flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>{cashLoadSuccess}</span>
            </div>
          )}

          <div className="space-y-4 text-xs font-mono">
            <div>
              <label className="text-slate-400 block mb-1">TARGET TERMINAL:</label>
              <select
                value={loadAtmId}
                onChange={e => setLoadAtmId(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-700 rounded-xl p-2.5 text-white"
              >
                {atms.map(a => (
                  <option key={a.id} value={a.id}>
                    {a.atm_code} ({a.city}) - Balance: INR {Number(a.cash_total).toLocaleString('en-IN')}
                  </option>
                ))}
              </select>
            </div>

            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
              <p className="text-slate-400">Select note counts to load:</p>
              {[100, 200, 500, 2000].map(denom => (
                <div key={denom} className="flex justify-between items-center">
                  <span>₹{denom} Notes Count:</span>
                  <input
                    type="number"
                    value={notesToLoad[denom] || 0}
                    onChange={e => setNotesToLoad(prev => ({ ...prev, [denom]: Math.max(0, parseInt(e.target.value) || 0) }))}
                    className="w-24 bg-slate-900 border border-slate-700 rounded-lg px-2 py-1 text-right text-white"
                  />
                </div>
              ))}
              <div className="border-t border-slate-800 pt-2 flex justify-between font-bold text-emerald-400">
                <span>Total Value to Add:</span>
                <span>INR {Object.entries(notesToLoad).reduce((a, [d, c]) => a + (Number(d) * c), 0).toLocaleString('en-IN')}</span>
              </div>
            </div>

            <button
              onClick={handleExecuteCashLoad}
              className="w-full py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-bold font-mono text-sm shadow-lg shadow-blue-600/30"
            >
              LOAD CASH INTO ATM
            </button>
          </div>
        </div>
      )}
      {/* MongoDB Compass View */}
      {activeTab === 'MONGODB' && (
        <div className="space-y-6">
          <div className="cyber-card p-6 rounded-2xl border-2 border-amber-500/40 space-y-4 shadow-[0_0_30px_rgba(245,158,11,0.15)]">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-amber-500/20 pb-4">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 rounded-xl bg-amber-500/20 border border-amber-500/40 flex items-center justify-center text-amber-400">
                  <Database className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white font-cyber flex items-center gap-2">
                    MongoDB Compass Integration
                    <span className="px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-[10px] font-mono">
                      ● {mongoInfo?.status || 'ONLINE'}
                    </span>
                  </h3>
                  <p className="text-xs text-zinc-400">
                    Direct local MongoDB instance connected for real-time data exploration in MongoDB Compass.
                  </p>
                </div>
              </div>

              <button
                type="button"
                disabled={isSyncingMongo}
                onClick={async () => {
                  setIsSyncingMongo(true);
                  setMongoSyncMsg(null);
                  try {
                    const res = await ApiService.syncMongo();
                    setMongoSyncMsg(`Full sync complete! ${Object.keys(res.synced_counts || {}).length} collections updated in MongoDB.`);
                    const inf = await ApiService.getMongoStatus();
                    setMongoInfo(inf);
                  } catch (e: any) {
                    alert(`Sync error: ${e.message}`);
                  } finally {
                    setIsSyncingMongo(false);
                  }
                }}
                className="btn-cyber-primary px-5 py-2.5 rounded-xl text-xs font-mono font-bold text-black flex items-center space-x-2 transition"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isSyncingMongo ? 'animate-spin' : ''}`} />
                <span>{isSyncingMongo ? 'SYNCING TO COMPASS...' : 'SYNC ALL DATA TO MONGODB'}</span>
              </button>
            </div>

            {mongoSyncMsg && (
              <div className="p-3 bg-emerald-950/60 border border-emerald-500/40 rounded-xl text-xs font-mono text-emerald-300 flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span>{mongoSyncMsg}</span>
              </div>
            )}

            {/* Compass Connection Instructions */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
              <div className="p-4 rounded-xl bg-black/60 border border-zinc-800 space-y-2">
                <span className="text-[10px] text-amber-400 uppercase tracking-widest block font-bold">
                  MONGODB COMPASS CONNECTION STRING:
                </span>
                <div className="p-2.5 bg-zinc-950 border border-amber-500/30 rounded-lg text-amber-300 font-bold select-all flex items-center justify-between">
                  <span>{mongoInfo?.url || 'mongodb://localhost:27017'}</span>
                  <span className="text-[10px] text-zinc-500">DEFAULT PORT</span>
                </div>
                <p className="text-[11px] text-zinc-400">
                  Open MongoDB Compass and paste this URL into the connection bar, then click <strong>Connect</strong>.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-black/60 border border-zinc-800 space-y-2">
                <span className="text-[10px] text-amber-400 uppercase tracking-widest block font-bold">
                  DATABASE NAME:
                </span>
                <div className="p-2.5 bg-zinc-950 border border-amber-500/30 rounded-lg text-white font-bold">
                  {mongoInfo?.database || 'securevault_db'}
                </div>
                <p className="text-[11px] text-zinc-400">
                  All banking transactions, customer profiles, ATM sensors, and incidents are stored in this database.
                </p>
              </div>
            </div>

            {/* Active Collections List */}
            <div className="space-y-3 pt-2">
              <span className="text-xs font-mono text-zinc-300 uppercase tracking-wider block font-bold">
                ACTIVE MONGODB COMPASS COLLECTIONS:
              </span>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3 font-mono text-xs">
                {(mongoInfo?.collections || [
                  'transactions', 'accounts', 'customers', 'cards', 'users', 'atms', 
                  'atm_sensors', 'incidents', 'alerts', 'security_events', 'audit_logs', 'detection_rules'
                ]).map((col: string) => (
                  <div key={col} className="p-3 bg-zinc-950/80 border border-zinc-800 hover:border-amber-500/40 rounded-xl flex items-center justify-between transition">
                    <span className="text-white font-bold">📂 {col}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20">LIVE</span>
                  </div>
                ))}
              </div>
            </div>

          </div>
        </div>
      )}

    </div>
  );
};
