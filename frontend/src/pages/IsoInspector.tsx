import React, { useState } from 'react';
import { 
  FileCode2, Send, CheckCircle2, AlertOctagon, 
  HelpCircle, ArrowRight, ShieldCheck, RefreshCw
} from 'lucide-react';
import { ApiService } from '../services/api';

export const IsoInspector: React.FC = () => {
  const [cardNumber, setCardNumber] = useState('4532015893024826');
  const [amount, setAmount] = useState('5000');
  const [atmCode, setAtmCode] = useState('SV-ATM-CHE-101');
  const [tamperMac, setTamperMac] = useState(false);
  const [result, setResult] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleInspect = async () => {
    setIsLoading(true);
    try {
      const token = ApiService.getToken();
      const res = await fetch('/api/v1/transactions/protocol/inspect', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          card_number: cardNumber,
          amount: parseFloat(amount) || 5000,
          atm_code: atmCode,
          stan: '048291',
          tamper_mac: tamperMac
        })
      });
      if (res.ok) {
        const data = await res.json();
        setResult(data);
      }
    } catch (err) {
      alert('Inspection request failed.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-[calc(100vh-4rem)] p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto space-y-6">
      {/* Banner */}
      <div className="p-3 bg-purple-950/40 border border-purple-500/30 rounded-2xl flex items-center justify-between text-xs text-purple-300 font-mono">
        <div className="flex items-center space-x-2">
          <FileCode2 className="w-4 h-4 text-purple-400" />
          <span>ISO 8583-STYLE SYNTHETIC FINANCIAL MESSAGE PROTOCOL (Educational Banking Simulation)</span>
        </div>
        <span className="text-[10px] text-slate-400">NEVER STORES RAW PAN</span>
      </div>

      {/* Header */}
      <div className="glass-panel p-5 rounded-2xl border-slate-800 space-y-1">
        <h1 className="text-xl font-bold text-white">Transaction Protocol Inspector</h1>
        <p className="text-xs text-slate-400">
          Inspect and verify synthetic ISO 8583 MTI 0200/0210 financial requests, data elements (DE), and cryptographic MAC checksums.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Input Parameters Form (Cols 4) */}
        <div className="lg:col-span-4 glass-panel p-5 rounded-2xl border-slate-800 space-y-4">
          <h2 className="text-sm font-bold text-white uppercase font-mono tracking-wider">Payload Parameters</h2>

          <div className="space-y-3 text-xs">
            <div>
              <label className="text-slate-400 block font-mono mb-1">CARD NUMBER (PAN)</label>
              <input
                type="text"
                value={cardNumber}
                onChange={e => setCardNumber(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-white font-mono"
              />
              <span className="text-[10px] text-slate-500 font-mono mt-1 block">Always masked in UI & message output</span>
            </div>

            <div>
              <label className="text-slate-400 block font-mono mb-1">WITHDRAWAL AMOUNT (INR)</label>
              <input
                type="number"
                value={amount}
                onChange={e => setAmount(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-white font-mono"
              />
            </div>

            <div>
              <label className="text-slate-400 block font-mono mb-1">TERMINAL ID (DE 41)</label>
              <input
                type="text"
                value={atmCode}
                onChange={e => setAtmCode(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-white font-mono"
              />
            </div>

            <div className="pt-2">
              <label className="flex items-center space-x-2 cursor-pointer p-3 rounded-xl bg-slate-900 border border-slate-800">
                <input
                  type="checkbox"
                  checked={tamperMac}
                  onChange={e => setTamperMac(e.target.checked)}
                  className="rounded text-rose-500 focus:ring-0"
                />
                <span className="text-xs text-rose-400 font-mono font-bold">Simulate Tampered MAC (DE 64 Checksum Error)</span>
              </label>
            </div>

            <button
              onClick={handleInspect}
              disabled={isLoading}
              className="w-full py-3 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl transition flex items-center justify-center space-x-2 shadow-lg shadow-blue-600/20"
            >
              <Send className="w-4 h-4" />
              <span>{isLoading ? 'TRANSMITTING MESSAGE...' : 'BUILD & TRANSMIT ISO 8583'}</span>
            </button>
          </div>
        </div>

        {/* Message Decomposition (Cols 8) */}
        <div className="lg:col-span-8 glass-panel p-5 rounded-2xl border-slate-800 space-y-6">
          {!result ? (
            <div className="flex flex-col items-center justify-center h-72 text-slate-500 space-y-2">
              <FileCode2 className="w-10 h-10 text-slate-700" />
              <p className="text-xs font-mono">Submit parameters to generate and inspect ISO 8583 message stages.</p>
            </div>
          ) : (
            <>
              {/* Protocol Transmission Pipeline */}
              <div className="space-y-2">
                <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block">Transmission Pipeline</span>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                  {result.stages.map((stg: any, idx: number) => (
                    <div key={idx} className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono font-bold text-cyan-400">{stg.stage}</span>
                        <span className={`text-[10px] font-mono font-bold ${
                          stg.status === 'PASSED' || stg.status === 'APPROVED' || stg.status === 'COMPLETED' ? 'text-emerald-400' : 'text-rose-400'
                        }`}>
                          {stg.status}
                        </span>
                      </div>
                      <p className="text-[10px] text-slate-400 font-sans">{stg.detail}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Data Elements (DE) Breakdown */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
                    MTI 0200 Financial Request Data Elements
                  </span>
                  <span className={`text-xs font-mono font-bold ${result.mac_valid ? 'text-emerald-400' : 'text-rose-400 animate-pulse'}`}>
                    {result.mac_valid ? 'MAC INTEGRITY VERIFIED (VALID)' : 'MAC CHECKSUM TAMPERED (DECLINED)'}
                  </span>
                </div>

                <div className="bg-slate-950 rounded-2xl border border-slate-800 divide-y divide-slate-900 font-mono text-xs">
                  {Object.entries(result.request_message.fields || {}).map(([key, field]: [string, any]) => (
                    <div key={key} className="p-3 flex items-center justify-between hover:bg-slate-900/40 transition">
                      <div className="space-y-0.5">
                        <div className="flex items-center space-x-2">
                          <span className="text-cyan-400 font-bold">{key}</span>
                          <span className="text-slate-300 font-medium">{field.name}</span>
                        </div>
                        <p className="text-[10px] text-slate-500 font-sans">{field.tooltip}</p>
                      </div>
                      <span className="text-white font-bold bg-slate-900 px-3 py-1 rounded-lg border border-slate-800">
                        {field.value}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* MTI 0210 Response */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between font-mono text-xs">
                <div>
                  <span className="text-slate-500 block text-[10px]">MTI 0210 FINANCIAL RESPONSE</span>
                  <span className="text-white font-bold">
                    Response Code {result.response_message.response_code}: {result.response_message.response_description}
                  </span>
                </div>
                <span className={`px-3 py-1 rounded-lg font-bold ${
                  result.response_message.response_code === '00' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'
                }`}>
                  {result.response_message.response_code === '00' ? 'APPROVED' : 'DECLINED'}
                </span>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
