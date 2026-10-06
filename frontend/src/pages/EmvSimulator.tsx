import React, { useState } from 'react';
import { 
  CreditCard, ShieldCheck, RefreshCw, CheckCircle2, 
  AlertOctagon, Repeat, Send, Key
} from 'lucide-react';
import { ApiService } from '../services/api';

export const EmvSimulator: React.FC = () => {
  const [cardPan, setCardPan] = useState('4532015893024826');
  const [amount, setAmount] = useState('2000');
  const [atc, setAtc] = useState(42);
  const [unpredictableNumber, setUnpredictableNumber] = useState('9B42A1F0');
  const [simulateCounterReplay, setSimulateCounterReplay] = useState(false);
  const [result, setResult] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleValidate = async () => {
    setIsLoading(true);
    try {
      const token = ApiService.getToken();
      const res = await fetch('/api/v1/security/cards/validate-chip', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          card_pan: cardPan,
          amount: parseFloat(amount) || 2000,
          atc: atc,
          unpredictable_number: unpredictableNumber,
          simulate_counter_replay: simulateCounterReplay
        })
      });
      if (res.ok) {
        const data = await res.json();
        setResult(data);
      }
    } catch (err) {
      alert('Chip validation request failed.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-[calc(100vh-4rem)] p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto space-y-6">
      {/* Banner */}
      <div className="p-3 bg-emerald-950/40 border border-emerald-500/30 rounded-2xl flex items-center justify-between text-xs text-emerald-300 font-mono">
        <div className="flex items-center space-x-2">
          <CreditCard className="w-4 h-4 text-emerald-400" />
          <span>EMV-STYLE INTEGRATED CIRCUIT (IC) CHIP SIMULATION (Educational Security Model)</span>
        </div>
        <span className="text-[10px] text-slate-400">ARQC / ATC COUNTER CRYPTOGRAPHY</span>
      </div>

      {/* Header */}
      <div className="glass-panel p-5 rounded-2xl border-slate-800 space-y-1">
        <h1 className="text-xl font-bold text-white">EMV Smart Card Security Simulation</h1>
        <p className="text-xs text-slate-400">
          Simulate chip cryptographic handshakes, Application Transaction Counter (ATC) monotonic increments, and cryptogram replay rejection.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Form */}
        <div className="lg:col-span-5 glass-panel p-5 rounded-2xl border-slate-800 space-y-4">
          <h2 className="text-sm font-bold text-white uppercase font-mono tracking-wider">Chip Parameters</h2>

          <div className="space-y-3 text-xs font-mono">
            <div>
              <label className="text-slate-400 block mb-1">CARD PAN (MASKED)</label>
              <input
                type="text"
                value={cardPan}
                onChange={e => setCardPan(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-white"
              />
            </div>

            <div>
              <label className="text-slate-400 block mb-1">AMOUNT (INR)</label>
              <input
                type="number"
                value={amount}
                onChange={e => setAmount(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-white"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-slate-400 block mb-1">CHIP ATC COUNTER</label>
                <input
                  type="number"
                  value={atc}
                  onChange={e => setAtc(parseInt(e.target.value) || 1)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-white"
                />
              </div>
              <div>
                <label className="text-slate-400 block mb-1">UNPREDICTABLE NO.</label>
                <input
                  type="text"
                  value={unpredictableNumber}
                  onChange={e => setUnpredictableNumber(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-white"
                />
              </div>
            </div>

            <div className="pt-2">
              <label className="flex items-center space-x-2 cursor-pointer p-3 rounded-xl bg-slate-900 border border-slate-800">
                <input
                  type="checkbox"
                  checked={simulateCounterReplay}
                  onChange={e => setSimulateCounterReplay(e.target.checked)}
                  className="rounded text-rose-500 focus:ring-0"
                />
                <span className="text-xs text-rose-400 font-bold">Simulate ATC Replay Attack (Reused Counter)</span>
              </label>
            </div>

            <button
              onClick={handleValidate}
              disabled={isLoading}
              className="w-full py-3 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded-xl transition flex items-center justify-center space-x-2 shadow-lg shadow-emerald-600/20"
            >
              <Send className="w-4 h-4" />
              <span>{isLoading ? 'VALIDATING CHIP...' : 'TRANSMIT EMV CRYPTOGRAM'}</span>
            </button>
          </div>
        </div>

        {/* Results */}
        <div className="lg:col-span-7 glass-panel p-5 rounded-2xl border-slate-800 space-y-4">
          <h2 className="text-sm font-bold text-white uppercase font-mono tracking-wider">Cryptogram Verification</h2>

          {!result ? (
            <div className="flex flex-col items-center justify-center h-64 text-slate-500 space-y-2">
              <CreditCard className="w-10 h-10 text-slate-700" />
              <p className="text-xs font-mono">Submit parameters to validate chip cryptographic verification.</p>
            </div>
          ) : (
            <div className="space-y-4 text-xs font-mono">
              <div className={`p-4 rounded-xl border flex items-center justify-between ${
                result.result?.valid 
                  ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300' 
                  : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
              }`}>
                <div className="flex items-center space-x-3">
                  {result.result?.valid ? (
                    <CheckCircle2 className="w-6 h-6 text-emerald-400" />
                  ) : (
                    <AlertOctagon className="w-6 h-6 text-rose-400 animate-pulse" />
                  )}
                  <div>
                    <span className="font-bold text-sm block">
                      {result.result?.valid ? 'EMV APPLICATION CRYPTOGRAM VALIDATED' : 'CHIP VALIDATION REJECTED'}
                    </span>
                    <span className="text-[11px] opacity-80">{result.result?.status_description}</span>
                  </div>
                </div>
                <span className={`px-2.5 py-1 rounded-lg font-bold text-[11px] ${
                  result.result?.valid ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'
                }`}>
                  {result.result?.valid ? 'APPROVED' : 'DECLINED'}
                </span>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <div className="flex justify-between py-1 border-b border-slate-900">
                  <span className="text-slate-500">Masked PAN:</span>
                  <span className="text-white">{result.card_pan_masked}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-900">
                  <span className="text-slate-500">Generated ARQC:</span>
                  <span className="text-cyan-400 font-bold">{result.arqc}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-900">
                  <span className="text-slate-500">Application Counter (ATC):</span>
                  <span className="text-purple-400 font-bold">#{result.atc}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-900">
                  <span className="text-slate-500">Replay Protection:</span>
                  <span className="text-emerald-400 font-bold">Monotonic Counter Check Active</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
