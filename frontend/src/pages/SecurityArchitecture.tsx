import React, { useState } from 'react';
import {
  Layers, Shield, Key, Lock, Cpu, Server, Activity, Database, FileCheck, CheckCircle2, Terminal, ArrowRight
} from 'lucide-react';

interface TechItem {
  technology: string;
  category: string;
  standard: string;
  purpose: string;
  fileLocation: string;
}

const techMatrix: TechItem[] = [
  {
    technology: 'Python FastAPI',
    category: 'Application Server',
    standard: 'Async OpenAPI 3.1',
    purpose: 'Core backend REST/WebSocket micro-services, Pydantic schemas, and security routers',
    fileLocation: 'backend/app/main.py'
  },
  {
    technology: 'EventPipeline (10-Stage)',
    category: 'Detection & SIEM',
    standard: 'SIEM Architecture',
    purpose: 'Collect -> Normalize -> Correlate -> Risk Score -> Detection Rule -> Alert -> Incident -> Playbook -> Response -> Audit',
    fileLocation: 'backend/app/engines/event_pipeline.py'
  },
  {
    technology: 'UEBA Engine (pandas/numpy)',
    category: 'Behavior Analytics',
    standard: 'UEBA / Baseline Scoring',
    purpose: 'Calculates dynamic baseline deviation (amount, hour, velocity, city) producing 0-100 anomaly scores',
    fileLocation: 'backend/app/engines/ueba.py'
  },
  {
    technology: 'AES-256-GCM',
    category: 'Cryptography',
    standard: 'NIST SP 800-38D',
    purpose: 'Authenticated encryption at rest for sensitive transaction payloads with 96-bit unique nonces',
    fileLocation: 'backend/app/services/crypto_vault.py'
  },
  {
    technology: 'Ed25519 & HMAC-SHA256',
    category: 'Digital Signatures',
    standard: 'RFC 8032 / FIPS 198-1',
    purpose: 'Cryptographic signing of firmware manifests, audit block checkpoints, and transaction message envelopes',
    fileLocation: 'backend/app/services/crypto_vault.py'
  },
  {
    technology: 'X.509 PKI / Simulated CA',
    category: 'Identity & PKI',
    standard: 'RFC 5280',
    purpose: 'Real X.509 certificate generation, CRL/OCSP status checks, and simulated mTLS client verification for ATM fleet',
    fileLocation: 'backend/app/services/crypto_vault.py'
  },
  {
    technology: 'HSM Simulator & Key Vault',
    category: 'Key Management',
    standard: 'PCI HSM / FIPS 140-3 Concept',
    purpose: 'Software-isolated hardware security module with master key wrapping, slot rotation, and usage auditing',
    fileLocation: 'backend/app/services/crypto_vault.py'
  },
  {
    technology: 'Argon2id',
    category: 'Credential Verifiers',
    standard: 'RFC 9106 / OWASP',
    purpose: 'Memory-hard password hashing for administrative and staff portal users',
    fileLocation: 'backend/app/core/security.py'
  },
  {
    technology: 'Synthetic ISO 8583',
    category: 'Banking Protocols',
    standard: 'ISO 8583-1:2003 (Modeled)',
    purpose: 'MTI 0200/0210 financial transaction message builder, parser, PAN masking, and DE 64 MAC verification',
    fileLocation: 'backend/app/services/iso8583.py'
  },
  {
    technology: 'EMV Chip Simulation',
    category: 'Payment Protocols',
    standard: 'EMV Book 2 (Modeled)',
    purpose: 'Simulated Application Cryptogram (ARQC) validation and Application Transaction Counter (ATC) replay defense',
    fileLocation: 'backend/app/services/emv.py'
  },
  {
    technology: 'Tamper-Evident Audit Chain',
    category: 'Audit & Integrity',
    standard: 'NIST SP 800-92 / Blockchain Model',
    purpose: 'Cryptographic SHA-256 hash chaining of every state mutation with instant tamper detection and automated verification',
    fileLocation: 'backend/app/audit/chain.py'
  },
  {
    technology: 'OWASP API Top 10 Controls',
    category: 'API Defense',
    standard: 'OWASP API Security 2023',
    purpose: 'BOLA protection, rate-limiting tokens, strict JSON payload enforcement, and dynamic inventory reflection',
    fileLocation: 'backend/app/api/v1/protocols.py'
  }
];

export const SecurityArchitecture: React.FC = () => {
  const [selectedLayer, setSelectedLayer] = useState<number>(0);

  const layers = [
    {
      title: 'Layer 1: Perimeter & Edge Identity',
      desc: 'ATM Terminal fleet running client agents, OpenStreetMap dynamic geospatial clustering, and synthetic mTLS client certificate verification.',
      components: ['ATM Terminal Client Agent', 'PKI X.509 Device Certificate', 'TLS 1.3 Edge Termination', 'OpenStreetMap Provider']
    },
    {
      title: 'Layer 2: Zero-Trust Security Gateway',
      desc: 'Every incoming request traverses Authenticate -> Authorize -> Validate -> Device Trust -> Risk Evaluation before execution.',
      components: ['JWT / WebAuthn Guard', 'Argon2id Verifier', 'OWASP API Rate Limiter', 'Replay / Nonce Validator', 'MAC Verifier']
    },
    {
      title: 'Layer 3: Core Defensive Engines',
      desc: 'Centralized decision engines compute risk scores, evaluate dynamic detection rules, and model user/entity behavior deviations.',
      components: ['10-Stage Event Pipeline', 'UEBA Engine (pandas/numpy)', 'Risk Engine (0-100)', 'Rule Engine (RULE-SV-###)']
    },
    {
      title: 'Layer 4: Incident Response & SOAR',
      desc: 'Automatic alert deduplication, incident dossier creation, automated containment playbooks, and analyst investigation workflows.',
      components: ['Incident Correlator', 'Automated SOAR Playbooks', 'ATM Remote Lockdown', 'Forensic JSON Export']
    },
    {
      title: 'Layer 5: Vaults & Cryptographic Trust',
      desc: 'Cryptographic isolation where keys never leave the server; tamper-evident hash chaining protects audit integrity.',
      components: ['HSM Key Vault', 'AES-256-GCM Vault', 'Ed25519 Signatures', 'Tamper-Evident Audit Chain']
    }
  ];

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Layers className="w-6 h-6 text-blue-400" />
          SecureVault Defense-in-Depth Architecture
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Comprehensive blueprint of SecureVault’s layered defensive pipeline, zero-trust evaluation gates, and cryptographic trust anchors.
        </p>
      </div>

      {/* Layered Interactive Diagram */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-6">
        <h2 className="text-sm font-mono text-slate-300 font-bold uppercase tracking-wider">
          Interactive Layered Defense Model
        </h2>

        <div className="grid grid-cols-1 lg:grid-cols-5 gap-3">
          {layers.map((layer, idx) => (
            <div
              key={idx}
              onClick={() => setSelectedLayer(idx)}
              className={`p-4 rounded-xl border cursor-pointer transition flex flex-col justify-between ${
                selectedLayer === idx
                  ? 'bg-blue-950/40 border-blue-500 shadow-lg shadow-blue-950/50'
                  : 'bg-slate-950 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div>
                <div className="flex items-center justify-between">
                  <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                    selectedLayer === idx ? 'bg-blue-500/20 text-blue-400' : 'bg-slate-900 text-slate-500'
                  }`}>
                    L{idx + 1}
                  </span>
                  {selectedLayer === idx && <span className="w-2 h-2 rounded-full bg-blue-400 animate-pulse" />}
                </div>
                <h3 className="text-xs font-bold text-white mt-2 leading-snug">
                  {layer.title.split(':')[1]}
                </h3>
              </div>
              <div className="mt-3 text-[11px] font-mono text-slate-400 flex items-center gap-1">
                <span>Inspect</span>
                <ArrowRight className="w-3 h-3 text-blue-400" />
              </div>
            </div>
          ))}
        </div>

        {/* Selected Layer Deep Dive */}
        <div className="bg-slate-950 p-5 rounded-xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <h3 className="text-sm font-mono font-bold text-blue-400 uppercase">
              {layers[selectedLayer].title}
            </h3>
            <span className="text-xs font-mono text-slate-500">Defensive Domain</span>
          </div>
          <p className="text-sm text-slate-300">
            {layers[selectedLayer].desc}
          </p>
          <div className="space-y-2 pt-1">
            <span className="text-xs font-mono text-slate-400 uppercase">Key Enforcing Components:</span>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
              {layers[selectedLayer].components.map((comp, i) => (
                <div key={i} className="bg-slate-900/80 border border-slate-800 p-2.5 rounded-lg text-xs font-mono text-slate-200 flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                  <span>{comp}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Technology & Standards Matrix */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden space-y-4 p-6">
        <div>
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-indigo-400" />
            Technology to Defensive Purpose Traceability
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Every technology listed in SecureVault is actively implemented and verified in the codebase.
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-950 border-b border-slate-800 text-xs font-mono text-slate-400 uppercase">
              <tr>
                <th className="py-3 px-4">Technology</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Standard</th>
                <th className="py-3 px-4">Specific Purpose in SecureVault</th>
                <th className="py-3 px-4">Primary Code Location</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {techMatrix.map((item, idx) => (
                <tr key={idx} className="hover:bg-slate-800/30 transition">
                  <td className="py-3 px-4 font-mono font-bold text-white text-xs whitespace-nowrap">
                    {item.technology}
                  </td>
                  <td className="py-3 px-4 font-mono text-xs text-slate-400">
                    {item.category}
                  </td>
                  <td className="py-3 px-4 font-mono text-xs text-indigo-400 whitespace-nowrap">
                    {item.standard}
                  </td>
                  <td className="py-3 px-4 text-xs text-slate-300 max-w-sm">
                    {item.purpose}
                  </td>
                  <td className="py-3 px-4 font-mono text-xs text-cyan-400 whitespace-nowrap">
                    {item.fileLocation}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
