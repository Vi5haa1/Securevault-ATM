import React, { useState } from 'react';
import { Network, Shield, Server, Activity, Lock, AlertTriangle, ArrowRight, CheckCircle2, RefreshCw } from 'lucide-react';

interface NetworkNode {
  id: string;
  name: string;
  ip_cidr: string;
  status: 'ONLINE' | 'PROTECTED' | 'FILTERING';
  active_conns: number;
  blocked_conns: number;
  tls_version: string;
  role: string;
}

export const NetworkSecurity: React.FC = () => {
  const [selectedNode, setSelectedNode] = useState<NetworkNode | null>(null);

  const nodes: NetworkNode[] = [
    {
      id: 'ATM_VLAN',
      name: 'Isolated ATM Fleet VLAN',
      ip_cidr: '10.240.0.0/16',
      status: 'PROTECTED',
      active_conns: 16,
      blocked_conns: 3,
      tls_version: 'TLS 1.3 + Client Cert',
      role: 'Hardware ATM Terminal network isolated from customer and public traffic'
    },
    {
      id: 'EDGE_WAF',
      name: 'Perimeter Next-Gen Firewall / WAF',
      ip_cidr: '198.51.100.1/24',
      status: 'FILTERING',
      active_conns: 142,
      blocked_conns: 38,
      tls_version: 'TLS 1.3 / HSTS',
      role: 'DDoS mitigation, rate-limiting, geo-blocking, and synthetic attack filtering'
    },
    {
      id: 'API_GATEWAY',
      name: 'SecureVault Zero-Trust Gateway',
      ip_cidr: '10.100.1.10/32',
      status: 'ONLINE',
      active_conns: 84,
      blocked_conns: 12,
      tls_version: 'TLS 1.3',
      role: 'API request token validation, replay check, MAC validation, and rate limiter'
    },
    {
      id: 'TRANSACTION_SRV',
      name: 'Core ISO 8583 Transaction Service',
      ip_cidr: '10.100.2.20/32',
      status: 'ONLINE',
      active_conns: 28,
      blocked_conns: 1,
      tls_version: 'mTLS Internal',
      role: 'Financial accounting, double-entry ledger, and balance reservations'
    },
    {
      id: 'FRAUD_UEBA',
      name: 'UEBA & Risk Scoring Engine',
      ip_cidr: '10.100.3.30/32',
      status: 'ONLINE',
      active_conns: 31,
      blocked_conns: 0,
      tls_version: 'mTLS Internal',
      role: 'Statistical anomaly scoring (0-100), baseline deviations, and threat intel lookup'
    },
    {
      id: 'KEY_VAULT',
      name: 'HSM Cryptographic Key Vault',
      ip_cidr: '10.100.4.40/32',
      status: 'PROTECTED',
      active_conns: 9,
      blocked_conns: 0,
      tls_version: 'Strict Hardware Isolated',
      role: 'AES-256-GCM encryption, Ed25519 signing, and X.509 PKI certificate generation'
    }
  ];

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Network className="w-6 h-6 text-cyan-400" />
          Network Topology & Security Boundary Visualization
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Interactive map of SecureVault’s segmented network zones, mTLS verification boundaries, and live perimeter telemetry.
        </p>
      </div>

      {/* Network Overview Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
          <div className="text-xs font-mono text-slate-400 uppercase">Perimeter Status</div>
          <div className="text-2xl font-bold text-emerald-400 mt-1 flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
            PROTECTED
          </div>
          <div className="text-[11px] text-slate-400 mt-1">mTLS + Zero-Trust active</div>
        </div>
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
          <div className="text-xs font-mono text-slate-400 uppercase">Live Connections</div>
          <div className="text-2xl font-bold text-white mt-1">310</div>
          <div className="text-[11px] text-cyan-400 mt-1">Across 6 segmented subnets</div>
        </div>
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
          <div className="text-xs font-mono text-slate-400 uppercase">Blocked Ingress Attempts</div>
          <div className="text-2xl font-bold text-rose-400 mt-1">54</div>
          <div className="text-[11px] text-slate-400 mt-1">Rate limits & signature failures</div>
        </div>
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
          <div className="text-xs font-mono text-slate-400 uppercase">TLS Protocol Version</div>
          <div className="text-2xl font-bold text-purple-400 mt-1">TLS 1.3</div>
          <div className="text-[11px] text-slate-400 mt-1">Enforced across all endpoints</div>
        </div>
      </div>

      {/* Interactive Topology Graph */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-6">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono text-slate-400 uppercase font-bold">Segmented Ingress Flow</span>
          <span className="text-xs font-mono text-cyan-400">Click node for subnet telemetry</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {nodes.map(node => (
            <div
              key={node.id}
              onClick={() => setSelectedNode(node)}
              className={`p-4 rounded-xl border cursor-pointer transition space-y-3 ${
                selectedNode?.id === node.id
                  ? 'bg-cyan-950/30 border-cyan-500 shadow-md shadow-cyan-950/40'
                  : 'bg-slate-950 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-white flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5 text-cyan-400" />
                  {node.name}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  {node.status}
                </span>
              </div>
              <div className="text-xs text-slate-400 font-mono">
                Subnet: <span className="text-slate-200">{node.ip_cidr}</span>
              </div>
              <div className="grid grid-cols-2 gap-2 text-[11px] font-mono pt-2 border-t border-slate-900">
                <div>
                  <span className="text-slate-500 block">ACTIVE</span>
                  <span className="text-slate-200 font-bold">{node.active_conns} conns</span>
                </div>
                <div>
                  <span className="text-slate-500 block">BLOCKED</span>
                  <span className="text-rose-400 font-bold">{node.blocked_conns} drops</span>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Selected Node Details */}
        {selectedNode && (
          <div className="bg-slate-950 p-5 rounded-xl border border-slate-800 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <h3 className="text-sm font-mono font-bold text-cyan-400 uppercase">
                {selectedNode.name} Subnet Dossier
              </h3>
              <span className="text-xs font-mono text-slate-500">Security Zone</span>
            </div>
            <p className="text-xs text-slate-300">
              {selectedNode.role}
            </p>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono pt-2">
              <div>
                <span className="text-slate-500 block text-[10px]">ENCRYPTION</span>
                <span className="text-white font-bold">{selectedNode.tls_version}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">SUBNET CIDR</span>
                <span className="text-white font-bold">{selectedNode.ip_cidr}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">ACTIVE SESSIONS</span>
                <span className="text-cyan-400 font-bold">{selectedNode.active_conns}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">ANOMALIES DROPPED</span>
                <span className="text-rose-400 font-bold">{selectedNode.blocked_conns}</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
