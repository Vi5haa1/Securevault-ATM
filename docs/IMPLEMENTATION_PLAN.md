# SecureVault ATM - Implementation Plan & Architecture Specification

## Overview
SecureVault ATM is a comprehensive, production-grade cybersecurity ATM platform written primarily in Python (FastAPI, SQLAlchemy 2.0, Pydantic v2, Argon2id, Fernet, Pandas, ReportLab) with a modern React + TypeScript + Tailwind CSS frontend. It integrates full defensive banking capabilities, multi-tier threat detection, automated response playbooks, tamper-evident cryptographic audit logging, a realistic ATM touch interface, bank management portal, SOC/SIEM real-time dashboard, and an isolated attack simulation engine.

---

## Architecture & Layers
```
securevault-atm/
  backend/
    app/
      main.py                  # FastAPI app factory, CORS, exception handlers, security headers
      core/                    # Configuration, DB sessions, security helpers, JWT/crypto, dependencies
      db/                      # SQLAlchemy 2.0 models, base, session, migrations
      schemas/                 # Strict Pydantic v2 validation models
      api/v1/                  # REST & WebSocket routers (auth, atm, transactions, soc, audit, sim, etc.)
      services/                # Business logic: auth, pin_policy, otp, transaction, denomination, receipt
      security/                # Zero-Trust pipeline, RBAC enforcement, device fingerprinting, rate limiting
      engines/                 # Risk engine, behavior engine, threat detection, playbooks, notifications
      audit/                   # Append-only SHA-256 hash-chain writer and tamper verifier
      simulation/              # Safe simulated attack scenarios (Brute Force, Tamper, API abuse, etc.)
      tasks/                   # Background scheduler (APScheduler), sensor simulation, session cleanup
    tests/                     # Comprehensive pytest test suite (unit, integration, property tests)
    alembic/                   # Migration scripts
    pyproject.toml             # Python packaging, dependencies, tools configuration
  agents/                      # Standalone node agents (atm_agent.py, traffic_generator.py)
  cli/                         # Typer-powered admin CLI (securevault-cli.py)
  frontend/                    # React 18 + Vite + Tailwind + Lucide + Leaflet + Recharts + Zustand
  docs/                        # Full system architecture, threat model, security model, demo scripts
  docker-compose.yml           # Container orchestration (MySQL, Redis, Backend, Frontend)
  .env.example                 # Production-safe configuration template
```

---

## Phase Checklist

- [x] **Phase 1: Project Scaffolding & Environment Setup**
  - Python 3.12 environment, dependencies (`pyproject.toml` / `requirements.txt`)
  - Directory structure matching the prompt specifications
  - Initial configuration (`core/config.py`), logging, security middleware
  - Baseline documentation (`docs/IMPLEMENTATION_PLAN.md`, `docs/DECISIONS.md`, `docs/PROGRESS.md`)

- [x] **Phase 2: Database Layer & Domain Models (SQLAlchemy 2.0 + Alembic)**
  - Async SQLAlchemy 2.0 engine and session factory
  - Complete domain models: User, Customer, Account, Card, Atm, AtmCashInventory, AtmSensor, Transaction, BehaviorProfile, SecurityEvent, Alert, Incident, IncidentAction, IncidentNote, SecurityPolicy, AuditLog, Notification, OtpChallenge, RefreshToken, UserSession, TrustedDevice
  - Alembic migrations setup + Seed data generator (SUPER_ADMIN, BANK_ADMIN, SECURITY_ANALYST, ATM_OPERATOR, 25 Customers, 16 realistic ATMs across 4 major Indian cities, cash inventories, 60 days of realistic history)

- [x] **Phase 3: Cryptography, Auth & Session Security**
  - Argon2id password & PIN hashing (`argon2-cffi`)
  - PyJWT access & rotating refresh token management with token-family reuse detection
  - TOTP MFA (`pyotp`) + Fernet encrypted secret storage (`cryptography`)
  - In-app OTP challenge mechanism (hash comparison via `hmac.compare_digest`, 2-min expiry, max 3 attempts)
  - Strict PIN policy (`services/pin_policy.py`)
  - Progressive delay and account lockout after 5 failed attempts
  - Idle session tracking with force-kill and single active session per card

- [x] **Phase 4: Authorization (RBAC) & Zero-Trust Security Pipeline**
  - Central RBAC permissions matrix (`security/rbac.py`)
  - IDOR protection verifying account ownership on all data paths
  - Reusable Zero-Trust Pipeline (`security/zero_trust_pipeline.py`):
    `Authenticate -> Authorize -> Validate -> Risk Analysis -> Security Policy -> Execute -> Audit`
  - Zero-Trust decision rationale and execution tracing

- [x] **Phase 5: Core ATM & Banking Services**
  - Account and card services
  - Denomination dispensing algorithm (greedy note allocation with exact change verification)
  - Transaction processing with row-level locking (`SELECT ... FOR UPDATE`)
  - Idempotency key deduplication
  - PDF receipt generation (`reportlab`)
  - ATM heartbeat and inventory management

- [x] **Phase 6: Risk Scoring & Behavioral Analysis Engines**
  - Configurable `risk_engine.py` (points: amount z-score, location anomaly, velocity, untrusted device, auth failures)
  - Scoring levels: LOW (0-30), MEDIUM (31-60), HIGH (61-80), CRITICAL (81-100)
  - Data-driven `behavior_engine.py` (`pandas` / `numpy` baseline metrics)
  - Dynamic `SecurityPolicy` reloading

- [x] **Phase 7: Threat Detection & Incident Response System**
  - Threat detectors: Brute force, OTP abuse, API abuse/rate-limiting, Suspicious transaction, Impossible travel, Unauthorized access, ATM offline/low cash, Session abuse, Tamper
  - Automated playbooks (`engines/playbooks.py`) generating checklist of actions
  - Incident management lifecycle (OPEN -> INVESTIGATING -> CONTAINED -> RESOLVED)
  - Real-time WebSocket notifications & event broadcast

- [x] **Phase 8: Tamper-Evident Cryptographic Audit Logging**
  - SHA-256 hash-chained append-only audit log writer
  - Immutable table constraints (no update/delete)
  - Audit verifier (`audit/verifier.py`) with broken link pinpointing
  - Safe Tamper Demo endpoint for SOC analyst verification

- [x] **Phase 9: Secure API Endpoints & Rate Limiting**
  - FastAPI routers for auth, atm, accounts, transactions, admin, soc, incidents, alerts, audit, simulations, notifications, ws
  - Rate limiting middleware with IP and user token buckets
  - Comprehensive Pydantic v2 schemas (`extra="forbid"`)
  - Security headers (CSP, HSTS, X-Frame-Options, etc.)

- [x] **Phase 10: Standalone Agents & Admin CLI**
  - `agents/atm_agent.py`: Distributed ATM node simulator (heartbeat, sensors, simulated card swipes)
  - `agents/traffic_generator.py`: Realistic live banking traffic generator
  - `cli/securevault_cli.py`: Typer CLI for seeding, user creation, audit verify, simulation runner, incident export

- [x] **Phase 11: Modern React Frontend Application**
  - Vite + React 18 + TypeScript + Tailwind CSS
  - `/atm`: Interactive ATM kiosk with card insertion, masked PIN pad, OTP drawer, cash animation, balance inquiry, withdrawal, deposit, transfer, PDF receipt download, session timer
  - `/admin`: Customer, ATM, Cash Loading, and Security Policy management
  - `/soc`: Real-time SIEM dashboard, Leaflet ATM map, Recharts analytics, Live event feed, Incident response console, Audit integrity panel, Tamper demo
  - `/soc/simulations`: Safe attack simulation launcher with real-time detection & response feedback

- [x] **Phase 12: Testing, Verification & Containerization**
  - Pytest test suite covering Auth, Zero-Trust, Risk Engine, Denomination, Audit chain, Concurrency, and Simulations
  - Multi-stage Dockerfiles & `docker-compose.yml` (MySQL 8, Redis, Backend, Frontend)
  - Complete documentation (`README.md`, `ARCHITECTURE.md`, `SECURITY_MODEL.md`, `THREAT_MODEL.md`, `DEMO_SCRIPT.md`, `RESUME_BULLETS.md`)
