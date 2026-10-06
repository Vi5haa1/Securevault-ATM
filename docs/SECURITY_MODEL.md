# SecureVault ATM - Security Model & RBAC Specification

## 1. Role-Based Access Control (RBAC) Matrix

| Permission Token | Description | CUSTOMER | ATM_OPERATOR | SECURITY_ANALYST | BANK_ADMIN | SUPER_ADMIN |
|---|---|:---:|:---:|:---:|:---:|:---:|
| `atm:operate` | Execute withdrawals, deposits, transfers at terminal | ✅ | ❌ | ❌ | ❌ | ❌ |
| `account:view_own` | Inquire account balance & mini statement | ✅ | ❌ | ❌ | ✅ | ✅ |
| `atm:view` | Inspect ATM fleet operational status | ❌ | ✅ | ✅ | ✅ | ✅ |
| `atm:cash_load` | Replenish physical note denomination inventory | ❌ | ✅ | ❌ | ✅ | ✅ |
| `atm:maintenance`| Set ATM into maintenance mode | ❌ | ✅ | ❌ | ✅ | ✅ |
| `atm:sensors` | Update or simulate sensor states | ❌ | ✅ | ✅ | ✅ | ✅ |
| `atm:lockdown` | Enforce emergency lockdown or release terminal | ❌ | ❌ | ✅ | ❌ | ✅ |
| `soc:dashboard` | View live SIEM KPIs and Leaflet map | ❌ | ❌ | ✅ | ✅ | ✅ |
| `soc:alerts` | Acknowledge and resolve security alerts | ❌ | ❌ | ✅ | ✅ | ✅ |
| `soc:incidents` | Manage incident lifecycle & notes | ❌ | ❌ | ✅ | ✅ | ✅ |
| `soc:audit_verify`| Run cryptographic SHA-256 chain verification | ❌ | ❌ | ✅ | ✅ | ✅ |
| `soc:tamper_demo` | Run deliberate tamper injection and restore | ❌ | ❌ | ✅ | ❌ | ✅ |
| `soc:simulations` | Execute defensive in-app attack simulations | ❌ | ❌ | ✅ | ❌ | ✅ |
| `admin:customers` | Lock/unlock customer accounts & view profiles | ❌ | ❌ | ❌ | ✅ | ✅ |
| `admin:policies` | Edit dynamic risk weights, thresholds, limits | ❌ | ❌ | ❌ | ✅ | ✅ |
| `admin:staff` | Create and manage internal operator/analyst users| ❌ | ❌ | ❌ | ❌ | ✅ |

---

## 2. Insecure Direct Object Reference (IDOR) Defenses
1. **Server-Side Account Ownership Enforcement:** All account queries verify `Account.customer_id == authenticated_customer.id` via the database session dependency (`verify_account_ownership`).
2. **Deterministic Card Hashing:** Card numbers are stored as salted HMAC-SHA256 digests. Numerical card enumeration cannot leak user IDs.
3. **Audit of Probes:** Any request for an account not belonging to the authenticated token automatically triggers an `UNAUTHORIZED_ACCESS_ATTEMPT` Security Event and Alert in the SOC console.

---

## 3. Cryptographic Storage & Session Controls
- **PINs & Passwords:** Hashed with Argon2id (`time_cost=3, memory_cost=65536, parallelism=2`) with server-side pepper.
- **MFA Secrets:** Encrypted with Fernet symmetric keys derived from environment secret material.
- **Session Duration:** Kiosk sessions have an aggressive 60-second idle timeout with UI countdown ring.
- **Single Active Session Rule:** New card logins immediately invalidate any existing active session tokens on that card.
- **Token Rotation:** Refresh tokens rotate on every issue with RFC 6749 token family reuse detection.
