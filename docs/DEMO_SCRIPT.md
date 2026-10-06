# SecureVault ATM - 7-Minute Portfolio Interview Demo Script

This script provides an exact, high-impact 7-minute live demonstration flow showcasing the complete end-to-end defense-in-depth architecture of SecureVault ATM.

---

### Step 1: Normal Kiosk Transaction & ISO 8583 Inspector (Minute 0:00 - 1:15)
1. **Open Kiosk:** Navigate to `/atm`.
2. **Terminal Selection:** Choose `SV-ATM-CHE-101 (Chennai)`.
3. **Card Login:** Select cardholder **Rahul Sharma** (or enter card number `4532015893024826`) and PIN `4826`.
4. **Withdrawal:** Enter amount `₹3,000` and click **DISPENSE CASH**.
5. **Zero-Trust Trace:** Point out the live decision trace verifying PIN authentication, IDOR account check, and row-level balance reservation.
6. **Financial Protocol Inspection:**
   - In the top navigation, open **Protocols -> ISO 8583 Inspector** (`/transactions/protocol`).
   - Showcase the synthetic ISO 8583-style message: MTI `0200`, masked PAN `411122******9182` (PCI DSS compliant), DE 4 amount `000000300000`, and DE 64 HMAC-SHA256 MAC signature.
   - Click **EMV Chip Simulator** (`/security/cards`): show the simulated Application Cryptogram (ARQC) validation and ATC counter replay protection.

---

### Step 2: Explainable Risk Engine & UEBA Behavioral Anomaly (Minute 1:15 - 2:15)
1. **High-Risk Transaction:** In the Kiosk or Attack Lab, simulate a `₹95,000` withdrawal at 03:12 AM from an unmapped terminal in Delhi.
2. **Transparent Risk Breakdown:** Show the "Why this score?" factor breakdown:
   - `Amount Outlier Deviation` (+20 points)
   - `Unusual Night Hour` (+15 points)
   - `Foreign City Velocity Anomaly` (+25 points)
   - `Untrusted Device Fingerprint` (+15 points)
   - **Composite Score = 75/100 (HIGH)** -> Automatically enforces Step-Up MFA rather than silent approval.
3. **UEBA Engine:** Point out how the statistical distribution over 60-day customer history calculates this deviation using pandas/numpy baselines.

---

### Step 3: Brute Force Attack & Correlated Incident (Minute 2:15 - 3:30)
1. **Launch Attack:** Go to **Attack Lab** (`/soc/simulations`).
2. **Execute Simulation:** Click **Execute Attack** on **Brute Force PIN Attack**.
3. **Observation:**
   - 5 sequential failed PIN events are processed by the unified `EventPipeline`.
   - **Deduplication:** Instead of generating 5 separate alerts, all 5 events correlate into **ONE** unified incident (`SV-INC-2026-XXXXX`).
4. **Incident Investigation Console:**
   - Click **Incidents** (`/incidents`) or the incident link.
   - **Timeline Tab:** Walk through the chronological pipeline trace (Event Ingested -> Normalized -> Rule Matched -> Alert -> Incident Spawned -> Card Locked).
   - **Evidence Tab:** Review the attached immutable snapshot of ATM telemetry and correlated events.
   - **Forensic Export:** Click **Export Forensic Report** to download the JSON report containing the SHA-256 evidence integrity hash.

---

### Step 4: Physical ATM Tamper, Lockdown & Live Map (Minute 3:30 - 4:45)
1. **Trigger Tamper:** In Attack Lab, execute **ATM Hardware Tamper Alarm**.
2. **Perimeter Defense:** The microswitch chassis breach is ingested by `EventPipeline`.
3. **Open SOC Dashboard (`/soc`):**
   - Point to the **Geographic Fleet Map** powered by Leaflet + OpenStreetMap (no API key required, attribution visible).
   - Terminal `SV-ATM-CHE-101` in Chennai marker turns **RED (LOCKDOWN)** with an active pulse animation.
4. **ATM Security Profile Drawer:**
   - Click the marker to slide out the ATM Security Profile.
   - Review cash level, network latency, Ed25519 firmware integrity status, and active X.509 certificate.
   - Demonstrate the audited **Release from Lockdown** button (requires analyst documentation reason).

---

### Step 5: PKI Certificates, HSM Key Center & Secrets (Minute 4:45 - 5:45)
1. **PKI Certificate Center (`/security/certificates`):**
   - Show genuine synthetic X.509 certificates generated via Python `cryptography`.
   - Explain device mTLS authentication between ATM agents and the security gateway.
2. **HSM Key Management (`/security/keys`):**
   - Showcase master-key encrypted key slots (AES-256-GCM transaction encryption, HMAC MAC keys).
   - Demonstrate automated key rotation and immutable key usage audit log.
3. **Secrets Management (`/security/secrets`):**
   - Highlight the zero-exposure policy: rotation age and entropy metrics are audited without ever returning secret strings across API boundaries.

---

### Step 6: Tamper-Evident SHA-256 Audit Chain & Demo (Minute 5:45 - 6:30)
1. **Healthy State:** Check the header Audit pill: `HEALTHY / VALID`.
2. **Verify Audit Chain:** Click **Verify Chain** on the SOC overview or navbar.
3. **Tamper Demo (Educational):**
   - Click **Tamper Demo** on a synthetic test record.
   - The indicator immediately flips to **RED (INTEGRITY FAILURE)**.
   - The audit panel highlights the exact sequence number where the SHA-256 hash broken chain occurred (`Record #X expected digest != computed digest`).
4. **Self-Healing Restore:** Click **Restore Demo Data**; verification re-runs and returns to **HEALTHY**.

---

### Step 7: Security Posture, ATT&CK Matrix & Architecture (Minute 6:30 - 7:00)
1. **Security Posture (`/security/posture`):**
   - 9-category posture evaluation running automated tests (Authentication, API, Crypto, Audit, Network, etc.).
2. **MITRE ATT&CK Matrix (`/soc/attack-coverage`):**
   - Heatmap of enterprise techniques (T1110, T1078, T1200) displaying active rule coverage and defensive gaps.
3. **Defense-in-Depth Blueprint (`/security/architecture`):**
   - Show the 5-layer interactive architecture and the Technology-to-Purpose traceability matrix.
