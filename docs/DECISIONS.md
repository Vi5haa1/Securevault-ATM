# SecureVault ATM - Architectural & Security Decisions Log

This document records all architectural, technical, and security decisions made during the construction and complete upgrade of the SecureVault ATM platform.

### DECISION 001: Async Database Operations with Dual Drivers (MySQL & SQLite fallback)
- **Context:** Production requirements specify MySQL 8 with `aiomysql`/`asyncmy` and Docker orchestration. During local development/testing without live containers or external MySQL credentials, testing must run reliably and seamlessly.
- **Decision:** Use SQLAlchemy 2.0 async engine with configurable database URL (defaulting to MySQL `mysql+aiomysql://root:securevault_pwd@localhost:3306/securevault_atm`, and automatically supporting async SQLite `sqlite+aiosqlite:///securevault.db` for ephemeral tests and self-contained zero-config execution).
- **Security Impact:** Same strict transactional semantics, row locking, and column types across both platforms.

### DECISION 002: Hash-Chain Tamper-Evident Audit Design
- **Context:** Financial and SOC compliance requires tamper-evident logging where any modification to past transactions or security logs is cryptographically detectable.
- **Decision:** Implement a canonical SHA-256 hash chain: `hash = SHA256(prev_hash || sequence_no || actor_id || action || resource_type || resource_id || canonical_json(payload) || timestamp)`. Sequence numbers are monotonic and locked. Writes are strictly append-only.
- **Security Impact:** Guarantees complete audit trail integrity. Any DB tampering is detected immediately during the periodic verification or via the verification API.

### DECISION 003: Argon2id with Dual Salt Parameterization
- **Context:** ATM PINs are typically short (4-6 digits), making raw brute-forcing fast without sufficient key stretching.
- **Decision:** Use Argon2id via `argon2-cffi` with a pepper from environment variables plus individual cryptographic salts, applied with high memory cost (64MB) and multiple iterations for both staff passwords and customer PINs. Card numbers are stored as HMAC-SHA256 digests alongside masked last 4 digits.
- **Security Impact:** Resilient against offline rainbow-table and GPU-accelerated dictionary attacks even if PINs are 4-6 digits. Note: Real production payment PIN handling complies with ISO 9564 and PCI PIN HSM-based blocks; SecureVault implements a documented synthetic educational model.

### DECISION 004: Zero-Trust Transaction Pipeline
- **Context:** Traditional banking apps disperse checks across endpoints, leading to bypasses (e.g., forgotten limit checks or missing audit entries).
- **Decision:** Centralize all security and execution checks into an ordered `ZeroTrustPipeline`: `Authenticate -> Authorize -> Validate -> Risk Analysis -> Security Policy -> Execute -> Audit`.
- **Security Impact:** Impossible to execute a transaction without passing through risk scoring, policy evaluation, and audit logging. Each step attaches an auditable execution trace.

### DECISION 005: Safe Defensive Attack Simulations
- **Context:** Portfolio demonstration requires showcasing detection of Brute Force, ATM Tampering, API Abuse, Suspicious Transactions, Session Abuse, Firmware Tampering, and Certificate Failures.
- **Decision:** Simulations trigger the actual internal detection mechanisms using synthetic internal events, flagged with `is_simulated=true`. They never send network packets outside localhost or attack external infrastructure.
- **Security Impact:** 100% safe, non-destructive, fully compliant with defensive cybersecurity standards.

### DECISION 006: OpenStreetMap Tile Provider with Graceful Fallback
- **Context:** CartoDB and Mapbox tile layers previously showed "API KEY REQUIRED" error tiles when keys were missing or expired.
- **Decision:** Implement a `MapProvider` abstraction defaulting to OpenStreetMap tiles (`https://tile.openstreetmap.org/{z}/{x}/{y}.png`) with required attribution. If an alternative tile provider fails, it degrades seamlessly to OpenStreetMap rather than displaying error tiles.
- **Security Impact:** High UI reliability, zero vendor lock-in, zero credential leakage in client code.

### DECISION 007: Correlated Incident Deduplication in EventPipeline
- **Context:** An attack consisting of multiple events (e.g. 5 sequential failed PINs or rapid port scans) should not spawn 5 independent incidents, which leads to alert fatigue in SOC operations.
- **Decision:** In Stage 3 (CORRELATE), the pipeline evaluates sliding time windows (5 minutes) and entity keys (`card:{id}` or `atm:{id}`). When a detection rule fires, the pipeline links subsequent events to the existing open incident rather than duplicating tickets.
- **Security Impact:** Meets enterprise SIEM standards; prevents alert floods while maintaining complete event auditability.

### DECISION 008: Non-Destructive Auto-Migration via PRAGMA Column Inspection
- **Context:** In SQLite, adding new columns to existing tables using SQLAlchemy `create_all()` is ignored if tables already exist.
- **Decision:** Built `backend/app/db/migrate.py` to inspect PRAGMA table info at startup and run idempotent `ALTER TABLE ... ADD COLUMN` statements without wiping or corrupting existing demo accounts and transactions.
- **Security Impact:** Zero data loss during iterative model enhancements.

### DECISION 009: Simulated Internal PKI & X.509 Device Certificates
- **Context:** Real ATM fleets authenticate with the bank's security gateway using device certificates (mTLS).
- **Decision:** Implemented `PkiService` using the standard Python `cryptography` library to generate authentic X.509 certificates with RSA keypairs and SHA-256 fingerprints. In the developer environment, mTLS identity verification is simulated server-side against the internal CA without requiring complex local kernel TLS configuration.
- **Security Impact:** Realistic X.509 lifecycle (issue, rotate, revoke, CRL check) with zero operational friction.

### DECISION 010: Modeled ISO 8583 and EMV Specifications with PCI DSS PAN Masking
- **Context:** Payment networks use specialized binary/bitmap protocols (ISO 8583, EMV Book 2).
- **Decision:** Implemented synthetic Python modules `Iso8583Message` (MTI 0200/0210, STAN, Processing Code, DE 64 MAC) and `EmvChipSimulator` (ARQC cryptogram, ATC counter replay defense). Enforced PCI DSS PAN masking (`411122******9182`) everywhere in logs and UI.
- **Security Impact:** Demonstrates deep payment domain knowledge while ensuring zero storage or exposure of raw cardholder data.

### DECISION 011: Honest Educational / Simulated Lab Labeling Across All Interfaces
- **Context:** Software claiming payment or military-grade cybersecurity certifications without formal audits creates legal and professional risk.
- **Decision:** Affixed explicit educational badges ("EDUCATIONAL / SIMULATED CONTROL MAPPING", "HSM SIMULATION", "ISO 8583-STYLE SYNTHETIC MESSAGE") across all modules, headers, and compliance matrices.
- **Security Impact:** Professional, ethical, and transparent portfolio presentation.

### DECISION 012: Zero-Exposure Secrets Management
- **Context:** Key management dashboards often inadvertently leak private keys or secret values into frontend DOMs or API responses.
- **Decision:** The `/security/secrets` and `/security/keys` APIs return rotation dates, entropy bits, and slot identifiers, but NEVER return raw private keys or secret plaintext.
- **Security Impact:** Adheres to the principle of least privilege and zero trust.
