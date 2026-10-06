# SecureVault ATM (Python & TypeScript Defense-in-Depth Edition)

> **Enterprise Defensive Cybersecurity ATM Banking Platform, 10-Stage Event Pipeline, Threat Detection Engine & SOC SIEM Command Center**

SecureVault ATM is a complete, portfolio-grade defensive cybersecurity banking platform written in **Python 3.12** (FastAPI, SQLAlchemy 2.0, Pydantic v2, Argon2id, Cryptography, Pandas, NumPy, ReportLab) with a state-of-the-art **React 18 + TypeScript + Tailwind CSS** frontend. It transforms banking operations and attack simulations into **one connected defensive cybersecurity platform**: an event generated anywhere (a kiosk transaction, an automated sensor, an attack simulation) traverses a unified 10-stage pipeline (`COLLECT -> NORMALIZE -> CORRELATE -> RISK SCORE -> DETECTION RULE -> ALERT -> INCIDENT -> PLAYBOOK -> RESPONSE -> AUDIT`) and propagates live across all modules.

All operations are **simulated, synthetic, and strictly defensive**. Nothing interacts with external networks or real accounts.

---

## 🌟 Upgraded Architectural Capabilities

1. **Unified 10-Stage Defensive Security Pipeline (`EventPipeline`):**
   - Single backbone for kiosk transactions, hardware sensors, API gateway, and simulations.
   - Stage-by-stage pipeline execution trace (`duration_ms`, `result`, `stage`, `status`) attached to every normalized event.
   - Sliding-window correlation (5 minutes) grouping repeated attacks into **ONE** consolidated incident (e.g. 5 failed PINs correlate into 1 incident rather than 5 alerts).

2. **Leaflet + OpenStreetMap MapProvider Abstraction:**
   - Default OSM tile layer (`https://tile.openstreetmap.org/{z}/{x}/{y}.png`) with required attribution. Needs zero API keys.
   - Graceful fallback: If an alternative provider fails, it degrades automatically to OSM.
   - Real-time marker colors based on live fleet state: Green (Online), Yellow (Warning), Orange (High Risk), Red (Lockdown/Breached with radar pulse animation), Gray (Offline).
   - Interactive slide-out **ATM Security Profile Drawer** with hardware telemetry, Ed25519 firmware integrity, X.509 certificate status, and audited lockdown/release controls.

3. **Explainable Risk Engine & UEBA Behavior Analytics (`engines/ueba.py`):**
   - 60-day historical baseline analysis (pandas/numpy) computing typical amounts, operating hours, geographical locations, and terminal behaviors.
   - Produces 0-100 anomaly scores and persists a human-readable factor breakdown equation (`Why this score?`).

4. **Cryptographic Controls & Hardware Security (`CryptoVault`):**
   - **AES-256-GCM** authenticated encryption with unique 96-bit random nonces for data at rest.
   - **Ed25519 digital signatures** for firmware manifests and audit block checkpoints.
   - **HMAC-SHA256** message authentication codes (MAC) verifying financial request envelopes.
   - **Internal PKI & Simulated CA:** Genuine X.509 certificate generation via `cryptography`, serial tracking, CRL revocation, and mTLS client verification.
   - **HSM Simulator & Key Vault:** Master-key encrypted key storage, versioned key slot rotation, and immutable key usage audits.

5. **Banking & Hardware Protocol Inspectors:**
   - **Synthetic ISO 8583 Inspector (`/transactions/protocol`):** MTI 0200/0210 messages, STAN, Processing Code, DE 64 MAC verification, and strict PCI DSS PAN masking (`411122******9182`).
   - **EMV Chip Simulator (`/security/cards`):** Application Transaction Counter (ATC), Application Cryptogram (ARQC) validation, and cryptogram replay rejection.

6. **SIEM Event Explorer & Dynamic Detection Rules:**
   - `/soc/events`: Paginated SIEM event table with severities, MITRE tactics, full pipeline traces, and JSONL/CSV forensic export.
   - `/soc/rules`: Editable database rules (`RULE-SV-001` through `012`) with structured JSON DSL, before/after diff audit, and dry-run tester.

7. **Incident Investigation Console (`/incidents`):**
   - Dossier page with chronological pipeline timeline, ATM telemetry snapshots at incident time, SOAR playbook traces, and analyst investigation notes.
   - One-click **Forensic JSON Report Export** containing an immutable SHA-256 evidence integrity hash.

8. **Tamper-Evident SHA-256 Audit Chain:**
   - Cryptographic blockchain-style hash chain linking all state mutations: `hash = SHA256(prev_hash || seq || payload)`.
   - Real **Verify Chain** engine, interactive **Tamper Demo** displaying the exact break sequence, and **Restore Demo Data**. Dynamic honesty indicator: `HEALTHY`, `DEGRADED`, `INTEGRITY FAILURE`, `OFFLINE`.

9. **Security Center Suite:**
   - **Security Posture (`/security/posture`):** Automated checks across 9 cybersecurity categories.
   - **Security Scanner (`/security/scanner`):** In-app self-checks with controlled demo flaw toggle.
   - **API Security (`/security/api`):** OWASP API Security Top 10 dynamic inventory and rate limiting.
   - **Threat Intelligence (`/threats`):** Local offline synthetic threat feed correlated in pipeline.
   - **MITRE ATT&CK Matrix (`/soc/attack-coverage`):** Defensive technique heatmap with rule coverage and gap identification.
   - **Network Topology (`/security/network`):** Segmented ATM VLAN, WAF, Gateway, and Vault boundaries.
   - **Secrets Management (`/security/secrets`):** Zero-exposure inventory showing rotation age and entropy bits.
   - **Standards Mapping (`/compliance`):** Traceability to PCI DSS 4.0.1, NIST SP 800-63B, OWASP, and ISO 8583.

---

## 🔐 Demo Credentials

| Role | Username / Identifier | Password / PIN | Description |
|---|---|---|---|
| **SUPER_ADMIN** | `admin` | `Admin@1234` | Full root access to all policies, staff, and fleet operations |
| **BANK_ADMIN** | `bankadmin` | `BankAdmin@1234` | Customer accounts, limits, policy thresholds, ATM fleet |
| **SECURITY_ANALYST** | `analyst1` | `Analyst@1234` | SOC SIEM console, live alerts, incident playbooks, audit verification |
| **ATM_OPERATOR** | `operator1` | `Operator@1234` | Cash note loading, maintenance mode toggle, sensor inspections |
| **CUSTOMER (Mumbai)** | Card: `4532015893024826` | PIN: `4826` | Rahul Sharma (Account: `SV1000000000`, Bal: ₹25,000+) |
| **CUSTOMER (Bangalore)** | Card: `5241890248107391` | PIN: `7391` | Priya Patel (Account: `SV1000000001`, Bal: ₹45,000+) |
| **CUSTOMER (Chennai)** | Card: `4111222233339182` | PIN: `9182` | Aravind Swamy (Account: `SV1000000002`, Bal: ₹32,000+) |
| **CUSTOMER (Delhi)** | Card: `4000123456786254` | PIN: `6254` | Ananya Sen (Account: `SV1000000003`, Bal: ₹60,000+) |

---

## 🚀 Quick Start Guide

### Local Development (Python + Vite)

1. **Backend Server:**
   ```powershell
   & "d:\SecureVault ATM\backend\.venv\Scripts\python.exe" -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
   ```
   *Swagger API Documentation:* [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

2. **Frontend Dev Server:**
   ```powershell
   cd frontend
   npm run dev
   ```
   *Application UI:* [http://localhost:5173](http://localhost:5173)

3. **Production Frontend Build:**
   ```powershell
   cd frontend
   npm run build
   ```
   *Compiles TypeScript and bundles via Vite with 0 errors.*

---

## 🧪 Automated Pytest Test Suite

Execute the complete automated test suite across all security, cryptographic, and pipeline engines:
```powershell
& "d:\SecureVault ATM\backend\.venv\Scripts\pytest.exe" backend/tests -v
```
**Test Results: 25 PASSED (100% Pass Rate)**
- ✅ `test_audit_chain.py`: Validates SHA-256 hash chaining and tamper detection
- ✅ `test_auth_and_lockout.py`: Validates PIN lockout thresholds and OTP challenge lifecycles
- ✅ `test_crypto_vault.py`: Validates AES-256-GCM, Ed25519 signatures, X.509 certs, and HSM key rotation
- ✅ `test_denomination.py`: Validates greedy cash dispensing and exact change constraints
- ✅ `test_iso_and_emv.py`: Validates ISO 8583 message formatting, PAN masking, MAC checks, and EMV chip validation
- ✅ `test_pin_policy.py`: Validates rejection of weak and sequential PINs
- ✅ `test_pipeline.py`: Validates 5 failed PINs correlate into 1 incident with pipeline trace
- ✅ `test_risk_engine.py`: Validates anomaly scoring, factor breakdown, and threat boundaries
- ✅ `test_simulations.py`: Validates defensive attack simulations through the real pipeline
- ✅ `test_ueba.py`: Validates statistical baseline deviation scoring and factor contributions
