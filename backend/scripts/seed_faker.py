#!/usr/bin/env python3
"""
SecureVault ATM: Deterministic Synthetic Banking Seed Generator
Generates realistic banking, fleet, transaction, and threat data.
Determinism: Seeded with 42 (Faker & random).
Output: backend/data/seed_data.json and backend/data/DEMO_CREDENTIALS.md.
"""

import sys
import os
import json
import random
import hashlib
import datetime
from decimal import Decimal
from pathlib import Path
from typing import List, Dict, Any, Tuple

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from faker import Faker
from argon2 import low_level

from app.core.config import settings
from app.core.security import hash_card_number, extract_last4
from app.audit.canonical import canonical_json
from app.audit.hash_chain import compute_audit_hash

# -----------------------------------------------------------------------------
# Configuration & Constants
# -----------------------------------------------------------------------------
SEED_VALUE = 42
fake = Faker("en_IN")
Faker.seed(SEED_VALUE)
random.seed(SEED_VALUE)

# Reference anchor timestamp for 100% deterministic reproducibility across runs
REFERENCE_NOW = datetime.datetime(2026, 10, 5, 12, 0, 0, tzinfo=datetime.timezone.utc)

OUTPUT_JSON_PATH = backend_dir / "data" / "seed_data.json"
CREDENTIALS_PATH = backend_dir / "data" / "DEMO_CREDENTIALS.md"


def deterministic_argon2_hash(secret: str, salt_identifier: str) -> str:
    """Computes a deterministic Argon2id hash using a derived 16-byte salt."""
    salt = hashlib.sha256(f"sv-argon2-salt-{salt_identifier}".encode("utf-8")).digest()[:16]
    h = low_level.hash_secret(
        secret=secret.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        type=low_level.Type.ID,
    )
    return h.decode("utf-8")


def deterministic_pin_hash(pin: str, salt_identifier: str) -> str:
    """Computes a deterministic peppered Argon2id PIN hash."""
    peppered = f"{settings.PIN_PEPPER}:{pin}"
    salt = hashlib.sha256(f"sv-pin-salt-{salt_identifier}".encode("utf-8")).digest()[:16]
    h = low_level.hash_secret(
        secret=peppered.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        type=low_level.Type.ID,
    )
    return h.decode("utf-8")


def generate_luhn_pan(prefix: str, length: int = 16) -> str:
    """Generates a synthetic PAN satisfying the Luhn algorithm checksum."""
    digits = [int(d) for d in prefix]
    while len(digits) < length - 1:
        digits.append(random.randint(0, 9))

    total = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 0:
            val = digit * 2
            if val > 9:
                val -= 9
            total += val
        else:
            total += digit
    check_digit = (10 - (total % 10)) % 10
    digits.append(check_digit)
    return "".join(map(str, digits))


# -----------------------------------------------------------------------------
# ATM Seed Specifications (16 nodes: 5 CHE, 4 BLR, 4 MUM, 3 DEL)
# -----------------------------------------------------------------------------
ATM_SPECS = [
    # Chennai (5)
    {"code": "SV-ATM-CHE-101", "city": "Chennai", "address": "Anna Salai, T. Nagar", "lat": 13.0418, "lng": 80.2341, "status": "ONLINE"},
    {"code": "SV-ATM-CHE-102", "city": "Chennai", "address": "Velachery Main Road", "lat": 12.9750, "lng": 80.2206, "status": "ONLINE"},
    {"code": "SV-ATM-CHE-103", "city": "Chennai", "address": "Poonamallee High Road, Kilpauk", "lat": 13.0805, "lng": 80.2452, "status": "ONLINE"},
    {"code": "SV-ATM-CHE-104", "city": "Chennai", "address": "OMR IT Corridor, Sholinganallur", "lat": 12.8996, "lng": 80.2279, "status": "ONLINE"},
    {"code": "SV-ATM-CHE-105", "city": "Chennai", "address": "Adyar Gandhi Nagar", "lat": 13.0067, "lng": 80.2570, "status": "MAINTENANCE"},

    # Bangalore (4)
    {"code": "SV-ATM-BLR-201", "city": "Bangalore", "address": "100 Feet Rd, Indiranagar", "lat": 12.9784, "lng": 77.6408, "status": "ONLINE"},
    {"code": "SV-ATM-BLR-202", "city": "Bangalore", "address": "Koramangala 5th Block", "lat": 12.9352, "lng": 77.6245, "status": "ONLINE"},
    {"code": "SV-ATM-BLR-203", "city": "Bangalore", "address": "Outer Ring Road, Bellandur", "lat": 12.9260, "lng": 77.6762, "status": "ONLINE"},
    {"code": "SV-ATM-BLR-204", "city": "Bangalore", "address": "Whitefield Main Rd", "lat": 12.9698, "lng": 77.7499, "status": "OFFLINE"},

    # Mumbai (4)
    {"code": "SV-ATM-MUM-301", "city": "Mumbai", "address": "BKC Bandra Kurla Complex", "lat": 19.0662, "lng": 72.8687, "status": "ONLINE"},
    {"code": "SV-ATM-MUM-302", "city": "Mumbai", "address": "Nariman Point, Marine Drive", "lat": 18.9256, "lng": 72.8242, "status": "ONLINE"},
    {"code": "SV-ATM-MUM-303", "city": "Mumbai", "address": "Linking Road, Bandra West", "lat": 19.0596, "lng": 72.8335, "status": "ONLINE"},
    {"code": "SV-ATM-MUM-304", "city": "Mumbai", "address": "Powai Hiranandani Gardens", "lat": 19.1176, "lng": 72.9060, "status": "ONLINE"},

    # Delhi (3)
    {"code": "SV-ATM-DEL-401", "city": "Delhi", "address": "Connaught Place, Inner Circle", "lat": 28.6315, "lng": 77.2167, "status": "ONLINE"},
    {"code": "SV-ATM-DEL-402", "city": "Delhi", "address": "Cyber Hub, DLF Phase 2", "lat": 28.4950, "lng": 77.0895, "status": "ONLINE"},
    {"code": "SV-ATM-DEL-403", "city": "Delhi", "address": "Hauz Khas Village", "lat": 28.5494, "lng": 77.1932, "status": "ONLINE"},
]


# -----------------------------------------------------------------------------
# Staff Users Specification (7 total)
# -----------------------------------------------------------------------------
STAFF_DEFS = [
    {
        "username": "admin",
        "email": "admin@securevault.bank",
        "phone": "+919876543210",
        "password_plain": "Admin@1234",
        "role": "SUPER_ADMIN",
        "description": "Root Platform Administrator",
    },
    {
        "username": "bankadmin",
        "email": "bankadmin@securevault.bank",
        "phone": "+919876543211",
        "password_plain": "BankAdmin@1234",
        "role": "BANK_ADMIN",
        "description": "Principal Banking Operations Admin",
    },
    {
        "username": "compliance_admin",
        "email": "compliance@securevault.bank",
        "phone": "+919876543217",
        "password_plain": "Compliance@1234",
        "role": "BANK_ADMIN",
        "description": "Regulatory Compliance & Risk Officer",
    },
    {
        "username": "analyst1",
        "email": "analyst1@securevault.bank",
        "phone": "+919876543212",
        "password_plain": "Analyst@1234",
        "role": "SECURITY_ANALYST",
        "description": "Lead SOC SIEM Security Analyst",
    },
    {
        "username": "analyst2",
        "email": "analyst2@securevault.bank",
        "phone": "+919876543213",
        "password_plain": "Analyst@1234",
        "role": "SECURITY_ANALYST",
        "description": "Incident Responder & Threat Hunter",
    },
    {
        "username": "operator1",
        "email": "operator1@securevault.bank",
        "phone": "+919876543214",
        "password_plain": "Operator@1234",
        "role": "ATM_OPERATOR",
        "description": "Field ATM Operations & Cash Courier Lead",
    },
    {
        "username": "operator2",
        "email": "operator2@securevault.bank",
        "phone": "+919876543215",
        "password_plain": "Operator@1234",
        "role": "ATM_OPERATOR",
        "description": "Hardware Diagnostics & Sensor Technician",
    },
]


# -----------------------------------------------------------------------------
# Primary Generator
# -----------------------------------------------------------------------------
def generate_dataset() -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
    """Generates the full synthetic dataset deterministically."""
    # Reset seeds to guarantee reproducibility
    Faker.seed(SEED_VALUE)
    random.seed(SEED_VALUE)

    demo_credentials_record: List[Dict[str, str]] = []

    # 1. Staff Users
    staff_users = []
    for s in STAFF_DEFS:
        pwd_hash = deterministic_argon2_hash(s["password_plain"], s["username"])
        staff_users.append({
            "username": s["username"],
            "email": s["email"],
            "phone": s["phone"],
            "password_hash": pwd_hash,
            "role": s["role"],
            "enabled": True,
            "locked": False,
            "mfa_enabled": False,
            "failed_login_count": 0,
        })
        demo_credentials_record.append({
            "type": "STAFF",
            "identifier": s["username"],
            "role": s["role"],
            "password_or_pin": s["password_plain"],
            "extra": s["description"],
        })

    # 2. ATMs, Inventories, Sensors, Certificates
    atms = []
    atm_inventory = []
    atm_sensors = []
    certificates = []

    # Root CA Certificate record
    root_cert_id = "CERT-ROOT-CA-01"
    certificates.append({
        "cert_id": root_cert_id,
        "subject": "CN=SecureVault Internal ATM Root CA, O=SecureVault ATM Banking Corp, C=IN",
        "issuer": "CN=SecureVault Internal ATM Root CA, O=SecureVault ATM Banking Corp, C=IN",
        "serial_number": "1000000000000001",
        "fingerprint": "9a8f4c2e6d1b3a5f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f",
        "valid_from": (REFERENCE_NOW - datetime.timedelta(days=365)).isoformat(),
        "valid_until": (REFERENCE_NOW + datetime.timedelta(days=3650)).isoformat(),
        "status": "VALID",
        "public_key_pem": "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIU...\n-----END CERTIFICATE-----",
        "atm_code": None,
    })

    sensor_types = ["CARD_READER", "PIN_PAD", "CASH_DISPENSER", "CAMERA", "TAMPER", "NETWORK", "DOOR"]

    for idx, spec in enumerate(ATM_SPECS):
        code = spec["code"]
        city = spec["city"]
        is_maint = spec["status"] == "MAINTENANCE"
        is_off = spec["status"] == "OFFLINE"

        # Deterministic coordinate jitter (approx 200-500 meters)
        lat_jitter = round((random.random() - 0.5) * 0.004, 6)
        lng_jitter = round((random.random() - 0.5) * 0.004, 6)
        lat = round(spec["lat"] + lat_jitter, 6)
        lng = round(spec["lng"] + lng_jitter, 6)

        # Inventory note counts
        multiplier = 0.05 if is_maint else 1.0
        n_100 = int(1000 * multiplier)
        n_200 = int(1000 * multiplier)
        n_500 = int(1000 * multiplier)
        n_2000 = int(200 * multiplier)
        total_cash = (100 * n_100) + (200 * n_200) + (500 * n_500) + (2000 * n_2000)

        # Firmware and certificate
        fw_ver = "SV-ATM-FW-3.4.1"
        fw_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        cert_id = f"CERT-{code}"

        # 1 ATM certificate expiring soon (e.g. SV-ATM-MUM-303)
        if code == "SV-ATM-MUM-303":
            cert_status = "EXPIRING"
            valid_until = REFERENCE_NOW + datetime.timedelta(days=5)
        else:
            cert_status = "VALID"
            valid_until = REFERENCE_NOW + datetime.timedelta(days=365)

        cert_fingerprint = hashlib.sha256(f"cert-fp-{code}".encode("utf-8")).hexdigest()

        certificates.append({
            "cert_id": cert_id,
            "subject": f"CN={code}, O=SecureVault ATM Banking Corp, C=IN",
            "issuer": "SecureVault Demo CA",
            "serial_number": f"20000000000000{idx+1:02d}",
            "fingerprint": cert_fingerprint,
            "valid_from": (REFERENCE_NOW - datetime.timedelta(days=180)).isoformat(),
            "valid_until": valid_until.isoformat(),
            "status": cert_status,
            "public_key_pem": f"-----BEGIN CERTIFICATE-----\nMIIC...{code}...=\n-----END CERTIFICATE-----",
            "atm_code": code,
        })

        # ATM Node record
        atms.append({
            "atm_code": code,
            "city": city,
            "address": spec["address"],
            "latitude": lat,
            "longitude": lng,
            "status": spec["status"],
            "network_status": "DISCONNECTED" if is_off else "CONNECTED",
            "cash_total": float(total_cash),
            "low_cash_threshold": 100000.0,
            "security_status": "SECURE" if not is_maint else "LOW_CASH_WARNING",
            "firmware_version": fw_ver,
            "firmware_hash": fw_hash,
            "secure_boot_enabled": True,
            "certificate_id": cert_id,
            "certificate_status": cert_status,
            "risk_score": 45 if is_maint else (20 if is_off else 5),
            "latency_ms": random.randint(18, 35),
            "cpu_usage": random.randint(15, 30),
            "memory_usage": random.randint(28, 48),
            "disk_usage": random.randint(40, 52),
            "under_attack": False,
            "last_heartbeat": (REFERENCE_NOW - datetime.timedelta(seconds=random.randint(5, 45))).isoformat(),
        })

        # Inventory
        for denom, count in [(100, n_100), (200, n_200), (500, n_500), (2000, n_2000)]:
            atm_inventory.append({
                "atm_code": code,
                "denomination": denom,
                "note_count": count,
            })

        # 7 Sensors (all NORMAL as requested)
        for st in sensor_types:
            atm_sensors.append({
                "atm_code": code,
                "sensor_type": st,
                "state": "NORMAL",
                "last_updated": REFERENCE_NOW.isoformat(),
            })

    # 3. 25 Bank Customers, Accounts, Cards, Devices, Profiles
    customers = []
    accounts = []
    cards = []
    devices = []

    # Preset reference identities to maintain compatibility with documentation/kiosk
    preset_customers = [
        ("rahul.sharma", "Rahul Sharma", "Mumbai", "4826", "4532015893024826"),
        ("priya.patel", "Priya Patel", "Bangalore", "7391", "5241890248107391"),
        ("aravind.swamy", "Aravind Swamy", "Chennai", "9182", "4111222233339182"),
        ("ananya.sen", "Ananya Sen", "Delhi", "6254", "4000123456786254"),
    ]

    city_pool = ["Chennai", "Bangalore", "Mumbai", "Delhi"]
    browsers = ["Chrome 122.0", "Firefox 124.0", "Safari 17.3", "Edge 122.0"]
    os_list = ["Android 14", "iOS 17.3", "Windows 11", "macOS Sonoma"]

    customer_meta = []  # Internal tracker for history generation

    for i in range(25):
        if i < len(preset_customers):
            uname, full_name, home_city, pin, card_pan = preset_customers[i]
            phone = f"+919876543{220 + i}"
            email = f"{uname}@example.com"
        else:
            full_name = fake.name()
            # Clean username ASCII
            clean_name = "".join(c for c in full_name.lower() if c.isalnum() or c == " ").strip().replace(" ", ".")
            uname = f"{clean_name}{random.randint(10, 99)}"
            email = f"{uname}@example.com"
            home_city = random.choice(city_pool)
            phone = f"+9198{random.randint(10000000, 99999999)}"
            pin = f"{random.randint(1000, 9999)}"
            # Generate Luhn-valid synthetic card PAN
            prefix = random.choice(["453201", "524189", "411122", "400012", "510510"])
            card_pan = generate_luhn_pan(prefix)

        pwd_plain = f"Pass@{pin}"
        pwd_hash = deterministic_argon2_hash(pwd_plain, uname)
        pin_hash = deterministic_pin_hash(pin, f"card-{i}")
        card_hash = hash_card_number(card_pan)
        last4 = extract_last4(card_pan)

        # Opening balance between 25,000 and 250,000 INR
        opening_balance = Decimal(f"{random.randint(25000, 250000)}.00")
        acc_num = f"SV10000000{i:02d}"
        acc_type = "CURRENT" if (i % 5 == 0) else "SAVINGS"

        # Customer record
        cust_record = {
            "username": uname,
            "full_name": full_name,
            "email": email,
            "phone": phone,
            "password_hash": pwd_hash,
            "home_city": home_city,
            "role": "CUSTOMER",
            "enabled": True,
        }
        customers.append(cust_record)

        # Account record
        acc_record = {
            "account_number": acc_num,
            "username": uname,
            "type": acc_type,
            "balance": float(opening_balance),
            "currency": "INR",
            "status": "ACTIVE",
            "daily_withdrawal_limit": 40000.0,
            "per_txn_limit": 20000.0,
        }
        accounts.append(acc_record)

        # Card record (Zero PAN storage rule strictly enforced)
        cards.append({
            "account_number": acc_num,
            "card_number_hash": card_hash,
            "last4": last4,
            "pin_hash": pin_hash,
            "status": "ACTIVE",
            "expiry": "12/28",
        })

        # 1-2 Trusted Devices
        num_devices = 2 if (i % 2 == 0) else 1
        for d_idx in range(num_devices):
            browser = browsers[(i + d_idx) % len(browsers)]
            os_name = os_list[(i * 2 + d_idx) % len(os_list)]
            dev_id = f"DEV-{hashlib.sha256(f'{uname}-{d_idx}'.encode()).hexdigest()[:12].upper()}"
            fp = f"FP-{uname}-{dev_id}-{browser.split()[0].lower()}"
            first_seen = REFERENCE_NOW - datetime.timedelta(days=random.randint(65, 120))
            last_seen = REFERENCE_NOW - datetime.timedelta(days=random.randint(1, 10))

            devices.append({
                "username": uname,
                "device_id": dev_id,
                "browser": browser,
                "os": os_name,
                "fingerprint": fp,
                "first_seen": first_seen.isoformat(),
                "last_seen": last_seen.isoformat(),
                "trusted": True,
            })

        # Record demo credential in dev-only documentation list
        demo_credentials_record.append({
            "type": "CUSTOMER",
            "identifier": uname,
            "role": "CUSTOMER",
            "password_or_pin": f"Pwd: {pwd_plain} | PIN: {pin} | Card Last4: {last4}",
            "extra": f"Acc: {acc_num} | City: {home_city}",
        })

        # Customer behavior baseline preferences
        secondary_city = random.choice([c for c in city_pool if c != home_city])
        typical_cities = [home_city] if (random.random() < 0.6) else [home_city, secondary_city]
        customer_meta.append({
            "cust_idx": i,
            "username": uname,
            "account_number": acc_num,
            "home_city": home_city,
            "typical_cities": typical_cities,
            "typical_min": Decimal("500.00"),
            "typical_max": Decimal("5000.00"),
            "typical_start_hour": 7,
            "typical_end_hour": 22,
            "current_balance": opening_balance,
            "withdrawals": [],
        })

    # 4. 60 Days of Transaction Baseline History & Anomaly Injection
    transactions = []
    atm_by_city: Dict[str, List[str]] = {}
    for spec in ATM_SPECS:
        if spec["status"] != "OFFLINE":
            atm_by_city.setdefault(spec["city"], []).append(spec["code"])

    txn_counter = 1

    # Plan transactions chronologically across 60 days
    # Days: 59 down to 0
    all_planned_txns = []

    for cm in customer_meta:
        # Each customer transacts 2 to 4 times per week across 60 days (approx 8.5 weeks -> 18 to 32 txns)
        # We select specific days for each customer
        step = random.randint(2, 4)
        for day_ago in range(0, 59, step):
            # Pick a time within typical operating hours
            hour = random.randint(cm["typical_start_hour"], cm["typical_end_hour"] - 1)
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            timestamp = REFERENCE_NOW - datetime.timedelta(days=day_ago, hours=REFERENCE_NOW.hour - hour, minutes=REFERENCE_NOW.minute - minute, seconds=second)

            city = random.choice(cm["typical_cities"])
            atm_options = atm_by_city.get(city, atm_by_city[cm["home_city"]])
            atm_code = random.choice(atm_options)

            # Determine transaction type (WITHDRAWAL: ~70%, BALANCE: ~12%, MINI_STATEMENT: ~10%, DEPOSIT: ~8%)
            roll = random.random()
            if roll < 0.70:
                ttype = "WITHDRAWAL"
                # Multiples of 100
                amount = Decimal(str(random.choice([500, 1000, 1500, 2000, 2500, 3000, 4000, 5000])))
            elif roll < 0.82:
                ttype = "BALANCE"
                amount = Decimal("0.00")
            elif roll < 0.92:
                ttype = "MINI_STATEMENT"
                amount = Decimal("0.00")
            else:
                ttype = "DEPOSIT"
                amount = Decimal(str(random.choice([2000, 5000, 10000, 15000])))

            all_planned_txns.append({
                "account_number": cm["account_number"],
                "atm_code": atm_code,
                "type": ttype,
                "amount": amount,
                "timestamp": timestamp,
                "is_anomaly": False,
                "anomaly_type": None,
                "city": city,
            })

    # Sort all planned transactions in strict chronological order
    all_planned_txns.sort(key=lambda x: x["timestamp"])

    # Inject 7 labeled anomalies (approx 1.5% of total transactions)
    # Selected indices evenly distributed
    anomaly_indices = [35, 95, 160, 230, 290, 350, 410]
    anomaly_types_cycle = ["UNUSUAL_HOUR", "HIGH_AMOUNT", "NEW_CITY", "VELOCITY_BURST"]

    for idx, a_idx in enumerate(anomaly_indices):
        if a_idx < len(all_planned_txns):
            target = all_planned_txns[a_idx]
            atype = anomaly_types_cycle[idx % len(anomaly_types_cycle)]
            target["is_anomaly"] = True
            target["anomaly_type"] = atype

            if atype == "UNUSUAL_HOUR":
                # Timestamp between 02:00 and 04:00 AM
                target["timestamp"] = target["timestamp"].replace(hour=3, minute=15)
            elif atype == "HIGH_AMOUNT":
                # High withdrawal within per_txn_limit but far above typical (e.g. 18,000 INR)
                target["type"] = "WITHDRAWAL"
                target["amount"] = Decimal("18000.00")
            elif atype == "NEW_CITY":
                # Transaction in a distant city not in typical cities
                cust_home = next(c["home_city"] for c in customer_meta if c["account_number"] == target["account_number"])
                foreign_city = "Delhi" if cust_home != "Delhi" else "Chennai"
                target["atm_code"] = atm_by_city[foreign_city][0]
                target["city"] = foreign_city
            elif atype == "VELOCITY_BURST":
                # Occurs just 2 minutes after prior transaction
                target["timestamp"] = all_planned_txns[a_idx - 1]["timestamp"] + datetime.timedelta(minutes=2)

    # Re-sort again to ensure strict chronological ordering after timestamp shifts
    all_planned_txns.sort(key=lambda x: x["timestamp"])

    # Replay balances forward in time order and build final transaction records
    account_balances = {cm["account_number"]: cm["current_balance"] for cm in customer_meta}
    customer_withdrawal_history: Dict[str, List[Decimal]] = {cm["account_number"]: [] for cm in customer_meta}

    for item in all_planned_txns:
        acc_num = item["account_number"]
        cur_bal = account_balances[acc_num]
        amt = item["amount"]
        ttype = item["type"]

        # Safeguard balance: if withdrawal or transfer exceeds balance, convert to deposit or adjust
        if ttype in ("WITHDRAWAL", "TRANSFER"):
            if cur_bal - amt < Decimal("500.00"):
                # Insufficient funds to withdraw safely; replenish via deposit first
                account_balances[acc_num] += Decimal("10000.00")
                cur_bal = account_balances[acc_num]
            account_balances[acc_num] -= amt
            customer_withdrawal_history[acc_num].append(amt)
        elif ttype == "DEPOSIT":
            account_balances[acc_num] += amt

        # Format risk score and factors
        if item["is_anomaly"]:
            r_score = random.randint(75, 95)
            r_level = "HIGH" if r_score < 85 else "CRITICAL"
            r_factors = {
                "is_anomaly": True,
                "anomaly_type": item["anomaly_type"],
                "score": r_score,
                "reason": f"Synthetic anomaly injected: {item['anomaly_type']}",
            }
        else:
            r_score = random.randint(5, 20)
            r_level = "LOW"
            r_factors = {
                "is_anomaly": False,
                "score": r_score,
                "baseline_compliance": "NORMAL",
            }

        rec_no = f"REC-TXN-{txn_counter:06d}"
        idem_key = f"IDEM-KEY-{acc_num}-{txn_counter:06d}"
        device_fp = f"kiosk-trusted-{item['atm_code'].lower()}"
        ip_addr = f"10.240.{random.randint(1, 15)}.{random.randint(10, 250)}"

        transactions.append({
            "account_number": acc_num,
            "atm_code": item["atm_code"],
            "type": ttype,
            "amount": float(amt),
            "status": "APPROVED",
            "risk_score": r_score,
            "risk_level": r_level,
            "risk_factors": r_factors,
            "device_fingerprint": device_fp,
            "ip_address": ip_addr,
            "idempotency_key": idem_key,
            "receipt_no": rec_no,
            "is_simulated": False,
            "is_anomaly": item["is_anomaly"],
            "anomaly_type": item["anomaly_type"],
            "created_at": item["timestamp"].isoformat(),
        })
        txn_counter += 1

    # Update opening balances in accounts table so final balance after replay matches
    for acc in accounts:
        acc["balance"] = float(account_balances[acc["account_number"]])

    # 5. Behavior Profiles (Computed from generated history)
    behavior_profiles = []
    for cm in customer_meta:
        w_list = customer_withdrawal_history[cm["account_number"]]
        if w_list:
            avg_w = float(sum(w_list) / len(w_list))
            # Standard deviation
            variance = sum((float(x) - avg_w) ** 2 for x in w_list) / len(w_list)
            std_w = round(variance ** 0.5, 2)
            min_w = float(min(w_list))
            max_w = float(max(w_list))
        else:
            avg_w = 2000.0
            std_w = 1000.0
            min_w = 500.0
            max_w = 5000.0

        # Frequency: transactions over 8.5 weeks
        num_cust_txns = len([t for t in transactions if t["account_number"] == cm["account_number"]])
        freq_per_week = round(num_cust_txns / 8.5, 2)

        behavior_profiles.append({
            "username": cm["username"],
            "avg_withdrawal": round(avg_w, 2),
            "std_withdrawal": std_w,
            "typical_min": min_w,
            "typical_max": max_w,
            "typical_start_hour": cm["typical_start_hour"],
            "typical_end_hour": cm["typical_end_hour"],
            "typical_cities": cm["typical_cities"],
            "txn_per_week_avg": freq_per_week,
            "updated_at": REFERENCE_NOW.isoformat(),
        })

    # 6. Detection Rules (RULE-SV-001 to RULE-SV-012)
    detection_rules = [
        {
            "rule_id": "RULE-SV-001",
            "name": "Multiple Failed PIN Attempts (Brute Force)",
            "description": "Triggered when 5 or more consecutive invalid PIN entries occur within 5 minutes on the same card or terminal.",
            "enabled": True,
            "severity": "HIGH",
            "event_types": ["FAILED_PIN", "FAILED_PIN_ATTEMPT"],
            "conditions": {"field": "count", "op": ">=", "threshold": 5, "window_seconds": 300, "group_by": "card_id"},
            "actions": ["LOCK_ACCOUNT", "LOCK_CARD", "CREATE_ALERT", "CREATE_INCIDENT", "NOTIFY_SOC"],
            "cooldown_seconds": 60,
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1110 - Brute Force",
        },
        {
            "rule_id": "RULE-SV-002",
            "name": "High-Value Transaction Anomaly",
            "description": "Triggered when a requested cash withdrawal exceeds 4x the customer's typical statistical baseline.",
            "enabled": True,
            "severity": "HIGH",
            "event_types": ["SUSPICIOUS_TXN", "LARGE_WITHDRAWAL"],
            "conditions": {"field": "risk_score", "op": ">=", "threshold": 70, "baseline_multiplier": 4.0},
            "actions": ["REQUIRE_MFA", "INCREASE_RISK", "CREATE_ALERT", "CREATE_INCIDENT", "NOTIFY_SOC"],
            "cooldown_seconds": 30,
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1078 - Valid Accounts",
        },
        {
            "rule_id": "RULE-SV-003",
            "name": "ATM Physical Tamper Breach",
            "description": "Zero-tolerance alarm triggered when physical cabinet, door, or tilt sensors indicate chassis breach.",
            "enabled": True,
            "severity": "CRITICAL",
            "event_types": ["ATM_TAMPER", "ATM_PHYSICAL_TAMPER"],
            "conditions": {"field": "sensor_state", "op": "==", "value": "ALERT"},
            "actions": ["LOCKDOWN_ATM", "TERMINATE_SESSIONS", "CREATE_ALERT", "CREATE_INCIDENT", "NOTIFY_SOC"],
            "cooldown_seconds": 0,
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1200 - Hardware Additions",
        },
        {
            "rule_id": "RULE-SV-004",
            "name": "API Rate Limit & Burst Abuse",
            "description": "Triggered when incoming HTTP transaction requests from a single client IP exceed maximum threshold.",
            "enabled": True,
            "severity": "HIGH",
            "event_types": ["API_RATE_LIMIT", "API_ABUSE"],
            "conditions": {"field": "count", "op": ">=", "threshold": 50, "window_seconds": 5},
            "actions": ["BLOCK_REQUEST", "CREATE_ALERT", "NOTIFY_SOC"],
            "cooldown_seconds": 120,
            "mitre_tactic": "Impact",
            "mitre_technique": "T1499 - Endpoint DoS",
        },
    ]

    # 7. Security Policies
    policies = [
        {
            "key": "RISK_WEIGHTS",
            "value": {"large_amount": 20, "new_location": 25, "unusual_time": 10, "velocity": 20, "new_device": 15, "failed_auth": 10},
            "description": "Dynamic weights for risk scoring factors",
        },
        {
            "key": "RISK_THRESHOLDS",
            "value": {"low_max": 30, "medium_max": 60, "high_max": 80, "critical_min": 81},
            "description": "Risk level classification boundaries",
        },
        {
            "key": "ATM_LIMITS",
            "value": {"default_daily_withdrawal": 40000.0, "default_per_txn": 20000.0},
            "description": "Default withdrawal limits",
        },
        {
            "key": "AUTH_POLICIES",
            "value": {"max_pin_attempts": 5, "session_timeout_seconds": 60},
            "description": "Lockout and timeout thresholds",
        },
    ]

    # 8. Synthetic Threat Indicators (RFC 5737 Reserved Documentation Addresses)
    threat_indicators = [
        {"indicator_type": "IP", "value": "198.51.100.22", "threat_category": "API_RATE_ABUSER", "confidence": 95, "severity": "HIGH", "tags": ["automated-scanner", "denial-of-service"]},
        {"indicator_type": "IP", "value": "198.51.100.45", "threat_category": "UNAUTHORIZED_ADMIN_PROBER", "confidence": 90, "severity": "HIGH", "tags": ["credential-stuffing", "privilege-escalation"]},
        {"indicator_type": "IP", "value": "203.0.113.88", "threat_category": "SKIMMER_RELAY_NODE", "confidence": 88, "severity": "CRITICAL", "tags": ["card-skimming", "pos-malware"]},
        {"indicator_type": "IP", "value": "192.0.2.14", "threat_category": "TOR_EXIT_NODE", "confidence": 75, "severity": "MEDIUM", "tags": ["anonymization", "suspicious-proxy"]},
        {"indicator_type": "IP", "value": "198.51.100.99", "threat_category": "DISTRIBUTED_BRUTE_FORCE_BOTNET", "confidence": 92, "severity": "HIGH", "tags": ["pin-harvesting", "botnet"]},
        {"indicator_type": "DOMAIN", "value": "c2-relay.synthetic-threat.net", "threat_category": "ATM_MALWARE_C2", "confidence": 99, "severity": "CRITICAL", "tags": ["blackbox-attack", "command-and-control"]},
    ]

    # 9. Audit Seed Records (Cryptographically chained from genesis)
    audit_seed = []
    prev_hash = settings.AUDIT_GENESIS_HASH
    audit_actions = [
        ("GENESIS_INIT", "SYSTEM", "ROOT", {"message": "Genesis audit block initialized."}),
        ("SEED_STAFF_USERS", "USER", "STAFF_BATCH", {"count": len(staff_users)}),
        ("SEED_ATM_NODES", "ATM", "FLEET_BATCH", {"count": len(atms), "cities": ["Chennai", "Bangalore", "Mumbai", "Delhi"]}),
        ("SEED_POLICIES", "SECURITY_POLICY", "CONFIG", {"policies_loaded": 4}),
        ("SEED_CUSTOMERS", "CUSTOMER", "CUST_BATCH", {"count": len(customers)}),
        ("SEED_TRANSACTIONS", "TRANSACTION", "HIST_BATCH", {"count": len(transactions), "days": 60}),
    ]

    for seq, (act, r_type, r_id, p_load) in enumerate(audit_actions, start=1):
        t_str = REFERENCE_NOW.strftime("%Y-%m-%dT%H:%M:%S")
        a_hash = compute_audit_hash(
            prev_hash=prev_hash,
            sequence_no=seq,
            actor_id="SYSTEM_INIT",
            action=act,
            resource_type=r_type,
            resource_id=r_id,
            payload=p_load,
            timestamp_str=t_str,
        )
        audit_seed.append({
            "sequence_no": seq,
            "actor_id": "SYSTEM_INIT",
            "actor_role": "SUPER_ADMIN",
            "action": act,
            "resource_type": r_type,
            "resource_id": r_id,
            "payload": p_load,
            "ip_address": "127.0.0.1",
            "created_at": REFERENCE_NOW.isoformat(),
            "prev_hash": prev_hash,
            "hash": a_hash,
        })
        prev_hash = a_hash

    # Meta Block
    dataset = {
        "meta": {
            "seed": SEED_VALUE,
            "generation_date": REFERENCE_NOW.isoformat(),
            "faker_locale": "en_IN",
            "row_counts": {
                "staff_users": len(staff_users),
                "customers": len(customers),
                "accounts": len(accounts),
                "cards": len(cards),
                "devices": len(devices),
                "atms": len(atms),
                "atm_inventory": len(atm_inventory),
                "atm_sensors": len(atm_sensors),
                "certificates": len(certificates),
                "transactions": len(transactions),
                "anomalies": sum(1 for t in transactions if t.get("is_anomaly")),
                "behavior_profiles": len(behavior_profiles),
                "detection_rules": len(detection_rules),
                "policies": len(policies),
                "threat_indicators": len(threat_indicators),
                "audit_seed": len(audit_seed),
            },
        },
        "staff_users": staff_users,
        "customers": customers,
        "accounts": accounts,
        "cards": cards,
        "devices": devices,
        "atms": atms,
        "atm_inventory": atm_inventory,
        "atm_sensors": atm_sensors,
        "certificates": certificates,
        "transactions": transactions,
        "behavior_profiles": behavior_profiles,
        "detection_rules": detection_rules,
        "policies": policies,
        "threat_indicators": threat_indicators,
        "audit_seed": audit_seed,
    }

    return dataset, demo_credentials_record


def write_demo_credentials(credentials: List[Dict[str, str]]):
    """Writes plain text demo credentials to dev-only DEMO_CREDENTIALS.md."""
    lines = [
        "# SecureVault ATM: Demo Development Credentials",
        "",
        "> **WARNING: DEMO ONLY — NEVER REUSE IN PRODUCTION**",
        "> This file contains development credentials generated for simulated test accounts.",
        "> This file is strictly excluded from version control (.gitignore).",
        "",
        "## Staff Accounts",
        "",
        "| Username | Role | Password | Description |",
        "|---|---|---|---|",
    ]
    for c in credentials:
        if c["type"] == "STAFF":
            lines.append(f"| `{c['identifier']}` | `{c['role']}` | `{c['password_or_pin']}` | {c['extra']} |")

    lines.extend([
        "",
        "## Customer Accounts (Sample Preview)",
        "",
        "| Username | Home City | Credentials / PIN | Account Info |",
        "|---|---|---|---|",
    ])
    for c in credentials:
        if c["type"] == "CUSTOMER":
            lines.append(f"| `{c['identifier']}` | {c['extra']} | `{c['password_or_pin']}` | - |")

    lines.append("")
    with open(CREDENTIALS_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def print_summary_table(meta: Dict[str, Any]):
    """Prints a structured summary table to terminal."""
    counts = meta["row_counts"]
    print("=" * 65)
    print("      SECUREVAULT ATM SYNTHETIC SEED GENERATION SUMMARY")
    print("=" * 65)
    print(f" Generator Seed         : {meta['seed']} (Faker + random)")
    print(f" Reference Anchor Date  : {meta['generation_date']}")
    print(f" Output JSON File       : {OUTPUT_JSON_PATH}")
    print(f" Demo Credentials File  : {CREDENTIALS_PATH}")
    print("-" * 65)
    print(f" {'Entity / Table':<30} | {'Count':>15} | {'Status':<10}")
    print("-" * 65)
    for entity, cnt in counts.items():
        print(f" {entity:<30} | {cnt:>15} | {'OK':<10}")
    print("=" * 65)
    pct = (counts['anomalies'] / counts['transactions']) * 100
    print(f" Anomaly Injection Rate : {counts['anomalies']} / {counts['transactions']} ({pct:.2f}%)")
    print("=" * 65)


def main():
    print("[*] Generating deterministic synthetic banking seed data...")
    dataset, credentials = generate_dataset()

    OUTPUT_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_JSON_PATH, "w", encoding="utf-8", newline="\n") as f:
        json.dump(dataset, f, indent=2)

    write_demo_credentials(credentials)
    print_summary_table(dataset["meta"])
    print("[+] Seed generation finished successfully.")


if __name__ == "__main__":
    main()
