import React, { useState, useEffect } from 'react';
import { 
  Key, ShieldCheck, ShieldAlert, Plus, Ban, 
  RefreshCw, CheckCircle2, AlertTriangle, X
} from 'lucide-react';
import { ApiService } from '../services/api';

export const CertificatesCenter: React.FC = () => {
  const [certs, setCerts] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [selectedCert, setSelectedCert] = useState<any | null>(null);
  const [revokeReason, setRevokeReason] = useState('');
  const [isRevoking, setIsRevoking] = useState(false);

  const fetchCerts = async () => {
    setIsLoading(true);
    try {
      const token = ApiService.getToken();
      const res = await fetch('/api/v1/security/certificates/', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setCerts(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRevoke = async () => {
    if (!revokeReason.trim() || !selectedCert) return;
    setIsRevoking(true);
    try {
      const token = ApiService.getToken();
      const res = await fetch(`/api/v1/security/certificates/${selectedCert.cert_id}/revoke`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ reason: revokeReason })
      });
      if (res.ok) {
        setSelectedCert(null);
        setRevokeReason('');
        fetchCerts();
      }
    } catch (err) {
      alert('Revocation failed.');
    } finally {
      setIsRevoking(false);
    }
  };

  useEffect(() => {
    fetchCerts();
  }, []);

  return (
    <div className="min-h-[calc(100vh-4rem)] p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto space-y-6">
      {/* Banner */}
      <div className="p-3 bg-blue-950/40 border border-blue-500/30 rounded-2xl flex items-center justify-between text-xs text-blue-300 font-mono">
        <div className="flex items-center space-x-2">
          <Key className="w-4 h-4 text-cyan-400" />
          <span>INTERNAL PKI / X.509 CERTIFICATE AUTHORITY (Python Cryptography Simulation)</span>
        </div>
        <span className="text-[10px] text-slate-400">RSA-2048 / SHA-256 SIGNED</span>
      </div>

      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 glass-panel p-5 rounded-2xl border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-white">PKI & Certificate Center</h1>
          <p className="text-xs text-slate-400">Client X.509 certificates establishing mutual TLS (mTLS) identities for ATM terminals</p>
        </div>

        <button
          onClick={fetchCerts}
          className="p-2.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-xl text-slate-300"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Certificate Table */}
      <div className="glass-panel rounded-2xl border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/80 text-slate-400 text-[11px] border-b border-slate-800 uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Certificate ID</th>
                <th className="py-3 px-4">Subject</th>
                <th className="py-3 px-4">Fingerprint (SHA-256)</th>
                <th className="py-3 px-4">Valid Until</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-900">
              {certs.map(c => {
                const isValid = c.status === 'VALID';
                const isRevoked = c.status === 'REVOKED';
                return (
                  <tr key={c.cert_id} className="hover:bg-slate-900/40 transition">
                    <td className="py-3 px-4 text-cyan-400 font-bold">{c.cert_id}</td>
                    <td className="py-3 px-4 text-slate-300">{c.subject}</td>
                    <td className="py-3 px-4 text-slate-400 text-[11px] truncate max-w-[160px]">
                      {c.fingerprint}
                    </td>
                    <td className="py-3 px-4 text-slate-400">
                      {c.valid_until ? new Date(c.valid_until).toLocaleDateString() : 'N/A'}
                    </td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        isValid ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                        isRevoked ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30 animate-pulse' :
                        'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                      }`}>
                        {c.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      {isValid ? (
                        <button
                          onClick={() => setSelectedCert(c)}
                          className="px-2.5 py-1 bg-rose-600/20 hover:bg-rose-600/30 text-rose-400 border border-rose-500/30 rounded-lg text-[10px] font-bold transition"
                        >
                          REVOKE
                        </button>
                      ) : (
                        <span className="text-slate-500 text-[10px]">{c.revocation_reason || 'INACTIVE'}</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Revocation Modal */}
      {selectedCert && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-3xl p-6 space-y-4 shadow-2xl">
            <div className="flex justify-between items-start">
              <div>
                <span className="text-xs font-mono text-rose-400 font-bold">REVOKE CLIENT CERTIFICATE</span>
                <h3 className="text-base font-bold text-white">{selectedCert.cert_id}</h3>
              </div>
              <button onClick={() => setSelectedCert(null)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <p className="text-xs text-slate-400 font-sans">
              Revoking this certificate immediately invalidates mutual TLS authentication for terminal {selectedCert.subject}.
            </p>

            <div>
              <label className="text-xs font-mono text-slate-400 block mb-1">MANDATORY REVOCATION REASON</label>
              <input
                type="text"
                placeholder="e.g. Hardware tampering suspected or key compromise"
                value={revokeReason}
                onChange={e => setRevokeReason(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-white text-xs font-mono"
              />
            </div>

            <button
              onClick={handleRevoke}
              disabled={isRevoking || !revokeReason.trim()}
              className="w-full py-2.5 bg-rose-600 hover:bg-rose-500 disabled:opacity-40 text-white font-bold text-xs rounded-xl transition flex items-center justify-center space-x-2"
            >
              <Ban className="w-4 h-4" />
              <span>{isRevoking ? 'REVOKING...' : 'CONFIRM CERTIFICATE REVOCATION'}</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
