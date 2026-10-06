import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Navbar } from './components/Navbar';
import { AtmKiosk } from './pages/AtmKiosk';
import { SocDashboard } from './pages/SocDashboard';
import { Simulations } from './pages/Simulations';
import { AdminPortal } from './pages/AdminPortal';
import { EventExplorer } from './pages/EventExplorer';
import { DetectionRules } from './pages/DetectionRules';
import { SecurityPosture } from './pages/SecurityPosture';
import { SecurityScanner } from './pages/SecurityScanner';
import { CertificatesCenter } from './pages/CertificatesCenter';
import { HsmKeyCenter } from './pages/HsmKeyCenter';
import { IsoInspector } from './pages/IsoInspector';
import { EmvSimulator } from './pages/EmvSimulator';
import { ApiSecurity } from './pages/ApiSecurity';
import { ThreatIntel } from './pages/ThreatIntel';
import { MitreCoverage } from './pages/MitreCoverage';
import { IncidentDetail } from './pages/IncidentDetail';
import { CompliancePage } from './pages/CompliancePage';
import { SecurityArchitecture } from './pages/SecurityArchitecture';
import { SecretsManagement } from './pages/SecretsManagement';
import { NetworkSecurity } from './pages/NetworkSecurity';

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
        <Navbar />
        <main className="flex-1">
          <Routes>
            <Route path="/" element={<Navigate to="/atm" replace />} />
            <Route path="/atm" element={<AtmKiosk />} />
            
            {/* SOC & SIEM */}
            <Route path="/soc" element={<SocDashboard />} />
            <Route path="/soc/events" element={<EventExplorer />} />
            <Route path="/soc/rules" element={<DetectionRules />} />
            <Route path="/soc/attack-coverage" element={<MitreCoverage />} />
            <Route path="/soc/simulations" element={<Simulations />} />
            
            {/* Incident Console */}
            <Route path="/incidents" element={<IncidentDetail />} />
            <Route path="/incidents/:id" element={<IncidentDetail />} />
            
            {/* Security Center */}
            <Route path="/security/posture" element={<SecurityPosture />} />
            <Route path="/security/scanner" element={<SecurityScanner />} />
            <Route path="/security/certificates" element={<CertificatesCenter />} />
            <Route path="/security/keys" element={<HsmKeyCenter />} />
            <Route path="/security/api" element={<ApiSecurity />} />
            <Route path="/security/secrets" element={<SecretsManagement />} />
            <Route path="/security/network" element={<NetworkSecurity />} />
            <Route path="/security/architecture" element={<SecurityArchitecture />} />
            
            {/* Protocols & Hardware */}
            <Route path="/transactions/protocol" element={<IsoInspector />} />
            <Route path="/security/cards" element={<EmvSimulator />} />
            
            {/* Threats & Compliance */}
            <Route path="/threats" element={<ThreatIntel />} />
            <Route path="/compliance" element={<CompliancePage />} />
            
            {/* Bank Administration */}
            <Route path="/admin" element={<AdminPortal />} />

            {/* Catch-all redirect */}
            <Route path="*" element={<Navigate to="/soc" replace />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
};

export default App;
