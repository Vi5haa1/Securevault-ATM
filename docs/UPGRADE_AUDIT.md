# SecureVault ATM: Upgrade Audit (Step 0)

## Executive Summary
This document records the architectural and operational audit of the existing **SecureVault ATM** cybersecurity platform before implementing the full comprehensive upgrade.

---

## 1. Stack and Technology Inventory

### Backend Stack
- **Language & Runtime:** Python 3.12 (venv at `backend/.venv`)
- **API Framework:** FastAPI 0.115+ (ASGI via Uvicorn)
- **Database ORM:** SQLAlchemy 2.0 (asyncio with `aiosqlite` and `aiomysql` driver support)
- **Database Engine:** SQLite local database (`securevault.db`) in workspace root; production-ready for MySQL 8.0 via `docker-compose.yml`.
- **Security & Cryptography:** `argon2-cffi`, `cryptography` (X.509, AES-GCM, HMAC, Ed25519), `pyjwt`, `pyotp`, `secrets`, `hmac`.
- **Data Science & SIEM Telemetry:** `pandas`, `numpy` for transaction velocity, UEBA, risk scoring and hourly analytics.
- **Reporting & CLI:** `reportlab` (PDF receipt generation), `typer`, `rich`, `faker`.
- **Testing:** `pytest` (14/14 test cases passing, 100% pass rate).

### Frontend Stack
- **Framework:** React 18.3.1 with TypeScript 5.4.5 and Vite 5.2.11
- **Styling:** Tailwind CSS 3.4.3 with custom glassmorphism styling (`glass-panel`, `glass-card`, `neon-glow`)
- **Routing:** React Router v6.23.1
- **Data Visualization & GIS:**
  - `leaflet` 1.9.4 & `react-leaflet` 4.2.1 (ATM fleet geographic tracking)
  - `recharts` 2.12.7 (Risk distribution bar chart, hourly volume, severity pie charts)
- **Icons:** `lucide-react` 0.383.0

---

## 2. Directory and Folder Layout

```
d:/SecureVault ATM/
├── .env.example
├── docker-compose.yml
├── README.md
├── securevault.db                 # Seeded SQLite database with 16 ATMs, 25 customers
├── powershell.cmd                 # Windows execution helper
├── backend/
│   ├── .venv/                     # Python 3.12 virtual environment
│   ├── pyproject.toml
│   ├── requirements.txt
│   ├── app/
│   │   ├── main.py                # FastAPI entrypoint, lifespan, CORS, security headers
│   │   ├── core/                  # config.py, security.py, deps.py (RBAC, JWT)
│   │   ├── db/                    # base.py, session.py, seed.py, models/models.py
│   │   ├── schemas/               # Pydantic schemas (atm, account, txn, incident, audit, etc.)
│   │   ├── services/              # auth.py, transaction.py, otp.py, receipt.py, hsm.py
│   │   ├── engines/               # threat_detection.py, risk_engine.py, behavior_engine.py, playbooks.py, notifier.py
│   │   ├── audit/                 # hash_chain.py, writer.py, verifier.py
│   │   ├── security/              # zero_trust_pipeline.py, rbac.py
│   │   ├── simulation/            # runner.py
│   │   └── api/v1/                # auth, atm, accounts, transactions, soc, incidents, alerts, audit, simulations, admin, ws
│   └── tests/                     # 14 pytest unit and integration tests
├── cli/
│   └── securevault_cli.py         # Typer CLI (seed, verify-audit, simulate, export-incidents)
├── docs/                          # Architecture, security model, implementation plan, demo script
└── frontend/
    ├── package.json
    ├── vite.config.ts
    ├── src/
    │   ├── main.tsx
    │   ├── App.tsx                # App routes (/atm, /soc, /soc/simulations, /admin)
    │   ├── index.css              # Cyberpunk dark slate theme tokens
    │   ├── components/Navbar.tsx  # Top navigation bar
    │   ├── pages/
    │   │   ├── AtmKiosk.tsx       # Virtual customer ATM terminal
    │   │   ├── SocDashboard.tsx   # SIEM operations, Leaflet map, incidents & analytics
    │   │   ├── Simulations.tsx    # Attack simulation trigger console
    │   │   └── AdminPortal.tsx    # Bank admin, accounts, ATM fleet, audit inspector
    │   ├── services/api.ts        # Axios/Fetch API client wrapper
    │   └── types/index.ts         # TypeScript definitions
```

---

## 3. Existing Models, Endpoints, and Pages

### Database Models (22 SQLAlchemy Models in `app/db/models/models.py`)
- **Identity & Access:** `User`, `UserRole`, `UserSession`, `RefreshToken`, `TrustedDevice`, `Notification`
- **Banking Domain:** `Customer`, `Account`, `AccountType`, `AccountStatus`, `Card`, `CardStatus`
- **ATM Infrastructure:** `Atm`, `AtmStatus`, `NetworkStatus`, `AtmCashInventory`, `AtmSensor`, `SensorType`, `SensorState`
- **Transactions & Intelligence:** `Transaction`, `TransactionType`, `TransactionStatus`, `RiskLevel`, `BehaviorProfile`
- **Security & SIEM:** `SecurityEvent`, `SeverityLevel`, `Alert`, `AlertStatus`, `Incident`, `IncidentStatus`, `IncidentAction`, `IncidentNote`, `SecurityPolicy`, `AuditLog`, `OtpChallenge`

### Existing API Endpoints (`/api/v1`)
- `/auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/verify-mfa`
- `/atm/cards/verify`, `/atm/cards/auth`, `/atm/session/balance`, `/atm/session/withdraw`, `/atm/session/receipt/{id}`
- `/accounts/me`, `/accounts/my-cards`, `/accounts/lock-card`, `/accounts/unlock-card`
- `/transactions/history`, `/transactions/verify-integrity`
- `/soc/kpis`, `/soc/map`, `/soc/analytics`, `/soc/events`
- `/incidents/`, `/incidents/{id}`, `/incidents/{id}/actions`, `/incidents/{id}/notes`
- `/alerts/`, `/alerts/{id}/ack`
- `/audit/logs`, `/audit/verify`, `/audit/tamper-demo`, `/audit/restore-demo`
- `/simulations/run`, `/simulations/reset-demo`
- `/admin/atms`, `/admin/atms/{id}/status`, `/admin/atms/{id}/refill`, `/admin/customers`, `/admin/users`
- `/ws/soc` (WebSocket real-time broadcast)

### Existing Pages
- `/atm` (Customer ATM Kiosk): Card insert, PIN check, balance inquiry, cash withdrawal, animated banknote dispenser, PDF receipt.
- `/soc` (SOC Dashboard): 6 KPI cards, Leaflet map of India, threat analytics charts, incident list, active alerts, audit integrity panel.
- `/soc/simulations` (Attack Lab): 6 simulation cards (Brute Force, Suspicious Transaction, Physical Tamper, API Abuse, Privilege Escalation, Session Replay).
- `/admin` (Bank Admin): Customer list, card lock/unlock, ATM cash refills, raw audit log inspector.

---

## 4. State Production Audit: Hardcoded vs. Dynamic vs. Mocked

### Places where state is currently mocked or hardcoded:
1. **Leaflet Tile Layer in `SocDashboard.tsx`:** Uses CartoDB dark tile URL `https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png` which displays "API KEY REQUIRED" without a key. Needs OpenStreetMap default with MapProvider abstraction.
2. **Dashboard Fallback Numbers:** In `SocDashboard.tsx`, fallback defaults exist when data is null: `{kpis?.atms?.total ?? 16}`, `{kpis?.atms?.online ?? 14}`, etc. While the API supplies real counts, if an endpoint returns null, hardcoded values are displayed. All values must be derived strictly from backend state.
3. **Map Marker Details:** ATM coordinates are seeded across 16 Indian cities (`SV-ATM-001` through `SV-ATM-016`), but missing standardized hierarchical naming (`SV-ATM-CHE-101`), pulse animations on attack, city clustering, and the comprehensive **ATM Security Profile drawer** with health telemetry, firmware hash, certificate status, and RBAC actions.
4. **Isolated Simulation Execution:** `SimulationRunner.run_simulation` performs direct model updates instead of routing through a single unified `EventPipeline` (`COLLECT -> NORMALIZE -> CORRELATE -> RISK SCORE -> DETECTION RULE -> ALERT -> INCIDENT -> PLAYBOOK -> RESPONSE -> AUDIT`).
5. **Detection Rules in Code:** Rules are currently hardcoded in Python functions in `threat_detection.py` and `risk_engine.py` instead of being stored in the database as editable data (`RULE-SV-###`) with JSON DSL, versioning, diff, dry-run, and hit counters.
6. **UEBA and Risk Transparency:** Anomaly score computation lacks a dedicated factor breakdown view ("Why this score?") and detailed customer/ATM behavior profile comparison pages.
7. **Security Center Pages Missing:** The following planned pages need full implementation:
   - `/soc/events` (SIEM Event Explorer with pipeline traces & JSON-lines export)
   - `/soc/rules` (Detection Rule Engine & Editor)
   - `/security/certificates` (PKI CA, X.509, mTLS)
   - `/security/keys` (HSM Simulator & KeyVault)
   - `/transactions/protocol` (ISO 8583-Style Inspector)
   - `/security/cards` (EMV Chip Cryptogram Simulator)
   - `/security/api` (OWASP API Top 10 Center & Inventory)
   - `/incidents/:id` (Dedicated Incident Investigation & Evidence Workspace)
   - `/security/posture` (Security Posture Dashboard)
   - `/threats` (Synthetic Threat Intelligence)
   - `/soc/attack-coverage` (MITRE ATT&CK Matrix)
   - `/security/network` (Network Security Visualization)
   - `/security/scanner` (Live Security Scanner & Headers Check)
   - `/security/secrets` (Secrets Management Status)
   - `/compliance` (PCI DSS 4.0.1, NIST 800-63B Standards Mapping)
   - `/security/architecture` (Interactive Architecture & Tech Mapping)

---

## 5. Upgrade Strategy & Compatibility

1. **Non-Destructive Evolution:** Preserve existing routes (`/atm`, `/soc`, `/soc/simulations`, `/admin`) and enhance them.
2. **Preserve Database Data:** Keep existing seeded accounts, cards, and ATMs in `securevault.db`, adding tables and columns as needed via non-destructive SQLAlchemy models and database verification.
3. **Centralized Backend Pipeline:** Create `app/engines/event_pipeline.py` as the single pipeline through which ATM events, simulations, API telemetry, and sensor signals pass.
4. **WebSocket/SSE Live Propagation:** Broadcast pipeline events immediately to the frontend so that all views (counters, map, incident drawer, audit chain) update in real-time.
5. **Honest Simulation Labeling:** All synthetic components (HSM, ISO 8583, EMV, Threat Intel, Compliance mappings) are clearly labeled with educational and defensive simulator notices.
