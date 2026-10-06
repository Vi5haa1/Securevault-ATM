# SecureVault ATM: Database & Seed Inspection Notes

**Date:** 2026-10-05  
**Inspector:** Antigravity IDE Autonomous Agent  
**Target:** SecureVault ATM Defensive Banking & SOC Platform  

---

## 1. System & Database Architecture

- **Primary Database Engine:** SQLite 3 via `sqlite+aiosqlite` (configured with WAL mode, `synchronous=NORMAL`, and busy timeout `10000ms`).
- **Database File Location:** `d:/SecureVault ATM/securevault.db` (Default resolution: root directory of workspace).
- **Secondary/Alternative Engine:** MySQL via `mysql+aiomysql` supported via `MYSQL_DATABASE_URL` in `app.core.config.Settings`.
- **ORM / Migrations:** SQLAlchemy 2.0 async engine (`create_async_engine`), `AsyncSessionLocal`, and non-destructive dynamic migration helper in `app.db.migrate.run_auto_migrations`.
- **Async Concurrency:** Session-per-request lifecycle with asyncio write locking on cryptographic audit chain.

---

## 2. Table Schemas, Columns, and Data Types

### Identity & Customer Tables
1. **`users`**
   - Columns: `id` (PK, int), `username` (varchar 64, unique), `email` (varchar 128, unique), `phone` (varchar 32, unique), `password_hash` (varchar 255, Argon2id), `role` (enum: `CUSTOMER`, `ATM_OPERATOR`, `SECURITY_ANALYST`, `BANK_ADMIN`, `SUPER_ADMIN`), `enabled` (bool), `locked` (bool), `failed_login_count` (int), `last_login_at` (datetime), `mfa_enabled` (bool), `mfa_secret_encrypted` (text), `created_at`, `updated_at`.
2. **`customers`**
   - Columns: `id` (PK, int), `user_id` (FK `users.id` on delete CASCADE, unique), `full_name` (varchar 128), `home_city` (varchar 64), `created_at`, `updated_at`.
3. **`trusted_devices`**
   - Columns: `id` (PK, int), `customer_id` (FK `customers.id` on delete CASCADE), `fingerprint` (varchar 128), `first_seen` (datetime), `last_seen` (datetime), `trusted` (bool), `created_at`, `updated_at`.
4. **`accounts`**
   - Columns: `id` (PK, int), `customer_id` (FK `customers.id` on delete CASCADE), `account_number` (varchar 20, unique), `type` (enum: `SAVINGS`, `CURRENT`), `balance` (numeric 14,2), `currency` (varchar 3, "INR"), `status` (enum: `ACTIVE`, `LOCKED`, `DISABLED`), `daily_withdrawal_limit` (numeric 10,2), `per_txn_limit` (numeric 10,2), `created_at`, `updated_at`.
5. **`cards`**
   - Columns: `id` (PK, int), `account_id` (FK `accounts.id` on delete CASCADE), `card_number_hash` (varchar 64, HMAC-SHA256, unique), `last4` (varchar 4), `pin_hash` (varchar 255, Argon2id with pepper), `pin_failed_attempts` (int), `status` (enum: `ACTIVE`, `LOCKED`, `EXPIRED`, `BLOCKED`), `expiry` (varchar 5, "MM/YY"), `pin_changed_at` (datetime), `created_at`, `updated_at`.

### ATM Fleet & Telemetry Tables
6. **`atms`**
   - Columns: `id` (PK, int), `atm_code` (varchar 32, unique), `city` (varchar 64), `address` (varchar 255), `latitude` (numeric 9,6), `longitude` (numeric 9,6), `status` (enum: `ONLINE`, `OFFLINE`, `MAINTENANCE`, `LOCKDOWN`, `DISABLED`), `network_status` (enum: `CONNECTED`, `DEGRADED`, `DISCONNECTED`), `cash_total` (numeric 14,2), `low_cash_threshold` (numeric 14,2), `security_status` (varchar 32), `firmware_version` (varchar 32), `firmware_hash` (varchar 64), `secure_boot_enabled` (bool), `certificate_id` (varchar 64), `certificate_status` (varchar 32), `risk_score` (int), `latency_ms` (int), `cpu_usage` (int), `memory_usage` (int), `disk_usage` (int), `under_attack` (bool), `last_heartbeat` (datetime), `created_at`, `updated_at`.
7. **`atm_cash_inventories`**
   - Columns: `id` (PK, int), `atm_id` (FK `atms.id` on delete CASCADE), `denomination` (int: 100, 200, 500, 2000), `note_count` (int), `created_at`, `updated_at`.
8. **`atm_sensors`**
   - Columns: `id` (PK, int), `atm_id` (FK `atms.id` on delete CASCADE), `sensor_type` (enum: `CARD_READER`, `PIN_PAD`, `CASH_DISPENSER`, `DOOR`, `CAMERA`, `TAMPER`, `NETWORK`), `state` (enum: `NORMAL`, `WARNING`, `ALERT`), `last_updated` (datetime).

### Transactions & UEBA Tables
9. **`transactions`**
   - Columns: `id` (PK, int), `account_id` (FK `accounts.id`), `atm_id` (FK `atms.id`), `type` (enum: `WITHDRAWAL`, `DEPOSIT`, `TRANSFER`, `BALANCE`, `MINI_STATEMENT`, `PIN_CHANGE`), `amount` (numeric 12,2), `status` (enum: `APPROVED`, `PENDING_VERIFICATION`, `BLOCKED`, `CANCELLED`, `FAILED`), `risk_score` (int), `risk_level` (enum: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), `risk_factors` (JSON), `device_fingerprint` (varchar 128), `ip_address` (varchar 45), `idempotency_key` (varchar 64, unique), `receipt_no` (varchar 32, unique), `related_account_id` (FK `accounts.id`), `is_simulated` (bool), `iso_mti` (varchar 8), `iso_stan` (varchar 16), `emv_atc` (int), `mac_digest` (varchar 64), `prev_txn_hash` (varchar 64), `txn_hash` (varchar 64), `created_at`, `updated_at`.
10. **`behavior_profiles`**
    - Columns: `id` (PK, int), `customer_id` (FK `customers.id` on delete CASCADE, unique), `avg_withdrawal` (numeric 10,2), `std_withdrawal` (numeric 10,2), `typical_min` (numeric 10,2), `typical_max` (numeric 10,2), `typical_start_hour` (int), `typical_end_hour` (int), `typical_cities` (JSON list), `txn_per_week_avg` (numeric 5,2), `updated_at` (datetime).

### Security, Cryptography & Audit Tables
11. **`certificates`**
    - Columns: `id` (PK, int), `cert_id` (varchar 64, unique), `subject` (varchar 128), `issuer` (varchar 128), `serial_number` (varchar 64, unique), `fingerprint` (varchar 64, unique), `valid_from` (datetime), `valid_until` (datetime), `status` (varchar 32: `VALID`, `EXPIRING`, `EXPIRED`, `REVOKED`), `revocation_reason` (varchar 128), `public_key_pem` (text), `private_key_encrypted` (text), `atm_id` (FK `atms.id`), `created_at`, `updated_at`.
12. **`detection_rules`**
    - Columns: `id` (PK, int), `rule_id` (varchar 32, unique), `name` (varchar 128), `description` (text), `enabled` (bool), `severity` (enum: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), `event_types` (JSON list), `conditions` (JSON), `actions` (JSON list), `cooldown_seconds` (int), `mitre_tactic` (varchar 64), `mitre_technique` (varchar 64), `version` (int), `hit_count` (int), `last_hit_at` (datetime), `updated_by` (varchar 64), `updated_at` (datetime).
13. **`threat_indicators`**
    - Columns: `id` (PK, int), `indicator_type` (varchar 32: `IP`, `DOMAIN`, `HASH`), `value` (varchar 128, unique), `threat_category` (varchar 64), `confidence` (int), `severity` (enum: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), `first_seen` (datetime), `last_seen` (datetime), `is_active` (bool), `tags` (JSON list), `created_at`.
14. **`security_policies`**
    - Columns: `id` (PK, int), `key` (varchar 64, unique), `value` (JSON), `description` (varchar 255), `updated_by` (FK `users.id`), `updated_at`.
15. **`audit_logs`**
    - Columns: `id` (PK, int), `sequence_no` (bigint, unique), `actor_id` (varchar 64), `actor_role` (varchar 32), `action` (varchar 64), `resource_type` (varchar 64), `resource_id` (varchar 64), `payload` (JSON), `ip_address` (varchar 45), `created_at` (datetime), `prev_hash` (varchar 64), `hash` (varchar 64).
    - Cryptographic Chain: `hash = SHA256(prev_hash || sequence_no || actor_id || action || resource_type || resource_id || canonical_json(payload) || timestamp)`.

---

## 3. Existing Baseline Data in `securevault.db`

Prior to running the new seed generator:
- `users`: 31 (6 staff + 25 customers)
- `customers`: 25
- `accounts`: 25
- `cards`: 25
- `trusted_devices`: 0
- `atms`: 16 (Chennai: 5, Bangalore: 4, Mumbai: 4, Delhi: 3)
- `atm_cash_inventories`: 64 (4 denominations per ATM)
- `atm_sensors`: 112 (7 sensors per ATM)
- `certificates`: 17 (1 Root CA + 16 ATMs)
- `behavior_profiles`: 25
- `detection_rules`: 12 (RULE-SV-001 through RULE-SV-012)
- `threat_indicators`: 6 (RFC 5737 doc IP ranges & synthetic C2)
- `security_policies`: 4 (`RISK_WEIGHTS`, `RISK_THRESHOLDS`, `ATM_LIMITS`, `AUTH_POLICIES`)
- `transactions`: 404 (simulated 60-day history)
- `audit_logs`: 25 (genesis block and mutation trail)

---

## 4. Seeding & Safety Design Requirements

1. **Deterministic Reproducibility:**
   - Seed both `Faker(locale="en_IN")` and Python `random` with seed **`42`**.
   - Running the generator multiple times must yield byte-identical `backend/data/seed_data.json`.
2. **Security & Privacy Safeguards:**
   - **No plaintext credentials:** Passwords and PINs are strictly hashed using Argon2id (`app.core.security.hash_password` and `app.core.security.hash_pin`).
   - Plain demo credentials written **only** to `backend/data/DEMO_CREDENTIALS.md` (added to `.gitignore`).
   - **PCI DSS PAN Protection:** Full card PANs are never persisted in the database or JSON. Only `card_number_hash` (HMAC-SHA256) and `last4` are saved.
   - **Threat Intel IPs:** Strictly confined to RFC 5737 documentation test blocks (`198.51.100.0/24` TEST-NET-2, `203.0.113.0/24` TEST-NET-3).
3. **Idempotency & Safe Migration:**
   - Loader operates inside a single atomic transaction.
   - Records are upserted or verified by unique natural keys (`username`, `account_number`, `card_number_hash`, `atm_code`, `idempotency_key`, `rule_id`, `value`).
   - `--reset` drops/clears seeded records only upon explicit user confirmation (`--yes` or interactive confirmation).
   - Audit trail records are created via `write_audit_log` so the SHA-256 cryptographic chain stays unbroken.
