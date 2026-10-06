# SecureVault ATM: Complete Upgrade Plan

This upgrade plan maps directly to the 34 numbered sections in the prompt. We will execute in logical, cohesive phases, running tests and verifying UI health after each phase.

---

## Master Checklist

- [ ] **Phase 1: Foundation, Geographic Map & Central Event Pipeline (Sections 1, 2, 3)**
  - [ ] Section 1: Fix Geographic ATM Map (OSM tiles, MapProvider abstraction, Indian coordinates, filters, ATM Security Profile drawer, live pulses)
  - [ ] Section 2: Security Event Pipeline (`engines/event_pipeline.py` with COLLECT -> NORMALIZE -> CORRELATE -> RISK -> RULE -> ALERT -> INCIDENT -> PLAYBOOK -> RESPONSE -> AUDIT, visible pipeline trace)
  - [ ] Section 3: Security Event Explorer (`/soc/events` SIEM-style table, drawer with trace, JSON-lines SIEM export `logs/siem_export.jsonl`)

- [ ] **Phase 2: Detection Rules, UEBA & Risk Engine (Sections 4, 5, 6)**
  - [ ] Section 4: Detection Rule Engine (`/soc/rules`, database-backed rules `RULE-SV-###`, JSON DSL, seed rules, dry-run test, diff, hit counters)
  - [ ] Section 5: UEBA: User and Entity Behavior Analytics (`engines/ueba.py` with pandas/numpy, user & ATM baselines, 0-100 anomaly score, Behavior Profile UI)
  - [ ] Section 6: Transparent Transaction Risk Engine (factor breakdown, weights policy, "Why this score?" panel)

- [ ] **Phase 3: ATM Security, PKI, HSM & Cryptographic Controls (Sections 7, 8, 9, 10)**
  - [ ] Section 7: ATM Security Layer (lockdown, reason-gated release, firmware integrity & secure boot simulation with HMAC/Ed25519)
  - [ ] Section 8: PKI / Certificate Center (`/security/certificates`, simulated CA using `cryptography` X.509, mTLS simulation, CRL/revocation)
  - [ ] Section 9: HSM Simulator and Key Management (`/security/keys`, KeyVault service, key slots, usage audit, master key encryption)
  - [ ] Section 10: Cryptographic Controls (TLS 1.3 config, AES-256-GCM data encryption at rest with 96-bit nonces, Argon2id, constant-time comparisons)

- [ ] **Phase 4: Banking Protocols, Chip Security & Zero-Trust (Sections 11, 12, 13, 14, 15, 16, 17)**
  - [ ] Section 11: Transaction Protocol Inspector: ISO 8583-Style (`/transactions/protocol`, synthetic builder/parser, 0200/0210, masked PAN)
  - [ ] Section 12: EMV-Style Card Security Simulation (`/security/cards`, chip cryptogram HMAC, ATC counter replay detection)
  - [ ] Section 13: API Security Center (`/security/api`, OWASP API Top 10, auto-generated API inventory, live telemetry)
  - [ ] Section 14: Zero-Trust Pipeline (pluggable pipeline with decision trace)
  - [ ] Section 15: Replay and Duplicate Protection (idempotency, nonce TTL, refresh-token family reuse revocation)
  - [ ] Section 16: Transaction Integrity and MAC Simulation (transaction hash chain, verify integrity, per-ATM MAC)
  - [ ] Section 17: Audit Chain: Make It Functional (SHA-256 chain, verification, tamper demo with exact break point, honest dynamic status badge)

- [ ] **Phase 5: Incidents, Playbooks, Posture & Telemetry (Sections 18, 19, 20, 21)**
  - [ ] Section 18: Incident Investigation Page (`/incidents/:id`, timeline, evidence tabs, playbook view, actions with reasons, export report)
  - [ ] Section 19: Automated Playbooks (data-driven playbooks for all attacks, active console, execution steps)
  - [ ] Section 20: Security Posture Dashboard (`/security/posture`, automated check functions across 9 categories, evidence & remediation)
  - [ ] Section 21: ATM Health Telemetry and Heartbeats (CPU, RAM, disk, latency, missed heartbeat offline detection)

- [ ] **Phase 6: Intelligence, Threat Matrix, Network & Auth (Sections 22, 23, 24, 25, 26, 27, 28)**
  - [ ] Section 22: Threat Intelligence (Synthetic) (`/threats`, offline dataset, suspicious IPs/domains, pipeline correlation)
  - [ ] Section 23: MITRE ATT&CK Defensive Mapping (`/soc/attack-coverage`, matrix/heat-map view by tactic)
  - [ ] Section 24: Network Security Visualization (`/security/network`, interactive diagram with live telemetry)
  - [ ] Section 25: Security Scanner and Headers Check (`/security/scanner`, live self-checks, demo failures toggle)
  - [ ] Section 26: Authentication Upgrades (WebAuthn/passkey simulation, device fingerprinting, NIST SP 800-63B)
  - [ ] Section 27: Secrets Management (`/security/secrets`, status page, rotation tracking)
  - [ ] Section 28: Standards Mapping Page (`/compliance`, PCI DSS 4.0.1, NIST 800-63B, OWASP Top 10)

- [ ] **Phase 7: Attack Lab, SOC Metrics, Scalable Navigation & Architecture (Sections 29, 30, 31, 32)**
  - [ ] Section 29: Attack Simulation Lab: Expanded Defensive Test Catalog (all 6 existing + new categorized catalog running through the unified pipeline)
  - [ ] Section 30: SOC Home and Metrics (MTTD, MTTR, detection rate, false positives, live dynamic counters)
  - [ ] Section 31: Navigation and Information Architecture (scalable RBAC sidebar/top-nav, preserving all existing routes)
  - [ ] Section 32: Security Architecture Page (`/security/architecture`, diagrams, technology mapping table)

- [ ] **Phase 8: Testing, Quality Assurance & Documentation (Sections 33, 34)**
  - [ ] Section 33: Testing and Quality (expanded pytest test suite covering all engines, rules, crypto, pipeline, frontend build & smoke tests)
  - [ ] Section 34: Documentation (`README.md`, `ARCHITECTURE.md`, `SECURITY_MODEL.md`, `THREAT_MODEL.md`, `DETECTION_RULES.md`, `PLAYBOOKS.md`, `STANDARDS_MAPPING.md`, `DEMO_SCRIPT.md`, `RESUME_BULLETS.md`)
