# SecureVault ATM - System Architecture Specification

## 1. High-Level System Architecture

```mermaid
graph TD
    subgraph Clients
        ATM[ATM Touch Kiosk /atm]
        SOC[SOC SIEM Dashboard /soc]
        Admin[Bank Admin Portal /admin]
        Agent[Autonomous ATM Agent Node]
        CLI[SecureVault Admin CLI]
    end

    subgraph Security_Perimeter[Zero-Trust Security Perimeter]
        WAF[Security Headers & Rate Limiting]
        Auth[Argon2id + PyJWT + TOTP MFA]
        RBAC[Fine-Grained RBAC & IDOR Guard]
    end

    subgraph Core_Engines[Core Defense Engines]
        ZTP[Zero-Trust Pipeline]
        Risk[Explainable Risk Engine]
        Beh[Behavioral Analysis Engine]
        Threat[Threat Detection Engine]
        Playbook[Automated Containment Playbooks]
        AuditW[Append-Only SHA-256 Hash Chain Writer]
    end

    subgraph Persistence_Layer[Data & Message Layer]
        MySQL[(MySQL 8 / Async SQLite)]
        AuditDB[(Immutable Audit Logs)]
        WS[FastAPI WebSocket Hub]
        SIEM_EXP[SIEM JSON/CEF Export File]
    end

    ATM --> WAF
    SOC --> WAF
    Admin --> WAF
    Agent --> WAF
    CLI --> Core_Engines

    WAF --> Auth --> RBAC --> ZTP
    ZTP --> Risk
    Risk --> Beh
    ZTP --> Threat
    Threat --> Playbook
    Playbook --> WS
    ZTP --> AuditW
    AuditW --> AuditDB
    AuditW --> SIEM_EXP
    ZTP --> MySQL
```

---

## 2. Zero-Trust Transaction Execution Pipeline

```mermaid
sequenceDiagram
    autonumber
    actor Customer as Customer / Kiosk
    participant Pipe as ZeroTrustPipeline
    participant Auth as 1. Authenticate
    participant Authz as 2. Authorize (IDOR Check)
    participant Valid as 3. Validate
    participant Risk as 4. Risk Analysis
    participant Policy as 5. Security Policy
    participant Exec as 6. Atomic DB Execution
    participant Audit as 7. SHA-256 Hash Chain Audit

    Customer->>Pipe: Execute Withdrawal Request
    Pipe->>Auth: Verify JWT & Active Kiosk Session
    Auth-->>Pipe: Identity Confirmed
    Pipe->>Authz: Verify Card & Account Ownership (IDOR Guard)
    Authz-->>Pipe: Ownership Cleared
    Pipe->>Valid: Validate Multiples of 100, Limits, ATM Status
    Valid-->>Pipe: Validation Cleared
    Pipe->>Risk: Calculate Score (Amount Deviation, Location, Velocity, Device)
    Risk-->>Pipe: Risk Score Evaluated (e.g. 15/100 LOW)
    Pipe->>Policy: Enforce Threat Thresholds & MFA Trigger
    Policy-->>Pipe: Policy Approved
    Pipe->>Exec: SELECT ... FOR UPDATE (Account & ATM Inventory)
    Exec-->>Pipe: Notes Dispensed & Balances Updated
    Pipe->>Audit: Append Monotonic Block to SHA-256 Hash Chain
    Audit-->>Pipe: Block Hash Committed
    Pipe-->>Customer: Transaction Approved + PDF Receipt Ready
```

---

## 3. Incident Response & Threat Containment Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Detection: Sensor Alert / Brute Force / Anomaly
    Detection --> IncidentCreated: Severity Evaluated (HIGH/CRITICAL)
    
    state IncidentCreated {
        [*] --> PlaybookTriggered
        PlaybookTriggered --> AtmLockdown: Hardware Tamper
        PlaybookTriggered --> CardAccountLock: 5 Failed PINs
        PlaybookTriggered --> KillSessions: Terminate Kiosk Tokens
        PlaybookTriggered --> BroadcastAlert: WebSocket Push to SOC
    }

    IncidentCreated --> INVESTIGATING: Assigned to SOC Analyst
    INVESTIGATING --> CONTAINED: Evidence Verified & Threat Isolated
    CONTAINED --> RESOLVED: Root Cause Documented & Signed Off
    RESOLVED --> [*]
```

---

## 4. Tamper-Evident SHA-256 Hash Chain Structure

```mermaid
graph LR
    subgraph Genesis_Block
        G_Prev["prev_hash: 000...000"]
        G_Seq["seq_no: 1"]
        G_Payload["payload: SYSTEM_INIT"]
        G_Hash["hash: SHA256(...)"]
    end

    subgraph Block_N
        B_Prev["prev_hash = Hash(Block 1)"]
        B_Seq["seq_no: 2"]
        B_Payload["payload: ATM_CASH_WITHDRAWAL"]
        B_Hash["hash: SHA256(prev_hash || seq || payload)"]
    end

    subgraph Block_N_Plus_1
        C_Prev["prev_hash = Hash(Block 2)"]
        C_Seq["seq_no: 3"]
        C_Payload["payload: BRUTE_FORCE_LOCKOUT"]
        C_Hash["hash: SHA256(prev_hash || seq || payload)"]
    end

    Genesis_Block --> Block_N --> Block_N_Plus_1
```
