# SecureVault ATM - Threat Model & STRIDE Analysis

## 1. STRIDE Analysis Matrix

| Threat Category | Potential Attack Vector | Impact | SecureVault Countermeasure & Verification | OWASP / ASVS Mapping |
|---|---|---|---|---|
| **Spoofing Identity** | Attacker attempts to guess ATM PIN or replay stolen credentials | Unauthorized funds withdrawal | Argon2id peppered hashing, 5-attempt card lockout, step-up TOTP/OTP challenge, single active session enforcement | A07:2021 Identification & Auth Failures |
| **Tampering with Data** | Attacker modifies balance or deletes past audit records in database | Audit evasion, fraudulent ledger | SHA-256 cryptographic hash chaining (`prev_hash`), append-only DB table structure, periodic verifier job | A08:2021 Software & Data Integrity Failures |
| **Repudiation** | Customer claims they never withdrew cash from ATM | Financial liability disputes | Cryptographic audit trail logs every step of Zero-Trust pipeline with timestamp, terminal ID, and receipt hash | ASVS V10: Malicious Code & Audit Trail |
| **Information Disclosure** | Sniffing network packets or examining server responses for card details | Exposure of PII and financial card numbers | Strict HTTPS/TLS, card numbers hashed with HMAC-SHA256, only last 4 digits stored in plaintext, masked in logs | A02:2021 Cryptographic Failures |
| **Denial of Service** | API request burst flood to exhaust ATM server connection pool | ATM terminals disconnected, users unable to transact | Token bucket rate limiting middleware, HTTP 429 enforcement, automated IP throttling, asynchronous event dispatch | A05:2021 Security Misconfiguration |
| **Elevation of Privilege** | Customer tampers with JWT role claim or calls admin endpoints | Unauthorized fleet lockdown, policy tampering | Cryptographically signed PyJWT (HS256/RS256), strict role enforcement dependencies, database-level RBAC checks | A01:2021 Broken Access Control |

---

## 2. Physical & Hardware Threat Modeling
- **ATM Skimming & Tamper Sensor:** If the physical cabinet chassis switch is breached, the terminal triggers an emergency alert, shuts down note dispensing, terminates sessions, and puts the ATM into `LOCKDOWN`.
- **Cash Note Dispensing Race Conditions:** Prevented via database-level `SELECT ... FOR UPDATE` row locks on both the customer Account balance and each `AtmCashInventory` denomination record.
