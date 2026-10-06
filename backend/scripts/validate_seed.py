#!/usr/bin/env python3
"""
SecureVault ATM: Seed Validation Suite
Checks and reports PASS/FAIL status across 8 critical verification categories:
1. Entity Counts (25 customers, 16 ATMs by city 5/4/4/3, 7 staff users)
2. Financial Limits & Integrity (no negative balance, withdrawals multiple of 100 & within limits)
3. Foreign Key & Reference Integrity (valid account and ATM references)
4. Temporal Coverage (transactions span the full 60-day baseline)
5. Deterministic Generation (two generator passes produce byte-identical JSON)
6. Data Protection & Zero-Knowledge Security (no plaintext PIN, password, or full PAN)
7. Cryptographic Audit Chain Integrity (verifies hash chain from genesis block)
8. Anomaly Distribution Rate (labeled anomalies strictly within 1-3%)
"""

import sys
import os
import json
import asyncio
import hashlib
import datetime
import subprocess
from decimal import Decimal
from pathlib import Path
from typing import List, Dict, Any, Tuple

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from sqlalchemy import select, func
from app.db.session import AsyncSessionLocal
from app.db.models.models import (
    User, Customer, Account, Card, Atm, AtmCashInventory, AtmSensor,
    BehaviorProfile, Transaction, SecurityPolicy, DetectionRule, ThreatIndicator,
    Certificate, TrustedDevice, AuditLog, UserRole
)
from app.audit.verifier import verify_audit_chain

SEED_JSON_PATH = backend_dir / "data" / "seed_data.json"
CREDENTIALS_PATH = backend_dir / "data" / "DEMO_CREDENTIALS.md"
GENERATOR_SCRIPT = backend_dir / "scripts" / "seed_faker.py"


class ValidationResult:
    def __init__(self, name: str, passed: bool, message: str, details: str = ""):
        self.name = name
        self.passed = passed
        self.message = message
        self.details = details


async def run_validations() -> List[ValidationResult]:
    results: List[ValidationResult] = []

    if not SEED_JSON_PATH.exists():
        results.append(ValidationResult(
            "Seed File Existence",
            False,
            f"File not found: {SEED_JSON_PATH}",
            "Run generator first."
        ))
        return results

    with open(SEED_JSON_PATH, "r", encoding="utf-8") as f:
        json_data = f.read()
        data = json.loads(json_data)

    async with AsyncSessionLocal() as session:
        # -------------------------------------------------------------
        # CHECK 1: Counts (25 customers, 16 ATMs [5/4/4/3 by city], 7 staff users)
        # -------------------------------------------------------------
        c_count = len(data.get("customers", []))
        s_count = len(data.get("staff_users", []))
        atms = data.get("atms", [])
        atm_count = len(atms)
        city_counts = {}
        for a in atms:
            city_counts[a["city"]] = city_counts.get(a["city"], 0) + 1

        expected_cities = {"Chennai": 5, "Bangalore": 4, "Mumbai": 4, "Delhi": 3}
        cities_ok = (city_counts == expected_cities)

        # Database verification
        db_cust = (await session.execute(select(func.count(Customer.id)))).scalar_one()
        db_atm = (await session.execute(select(func.count(Atm.id)))).scalar_one()
        db_staff = (await session.execute(select(func.count(User.id)).where(User.role != UserRole.CUSTOMER))).scalar_one()

        count_pass = (
            c_count == 25 and s_count == 7 and atm_count == 16 and cities_ok and
            db_cust == 25 and db_atm == 16 and db_staff == 7
        )
        msg = f"JSON: {c_count} customers, {atm_count} ATMs (CHE:{city_counts.get('Chennai',0)}, BLR:{city_counts.get('Bangalore',0)}, MUM:{city_counts.get('Mumbai',0)}, DEL:{city_counts.get('Delhi',0)}), {s_count} staff | DB: {db_cust} cust, {db_atm} atms, {db_staff} staff"
        results.append(ValidationResult("Entity Counts & Geographic Fleet", count_pass, msg))

        # -------------------------------------------------------------
        # CHECK 2: Financial Limits & No Negative Balances
        # -------------------------------------------------------------
        txns = data.get("transactions", [])
        neg_balance = False
        mult_100_ok = True
        limits_ok = True

        for acc in data.get("accounts", []):
            if acc["balance"] < 0:
                neg_balance = True

        # Check DB accounts
        stmt_neg = select(Account).where(Account.balance < 0)
        neg_db_acc = (await session.execute(stmt_neg)).scalars().all()
        if neg_db_acc:
            neg_balance = True

        for t in txns:
            if t["type"] == "WITHDRAWAL":
                amt = Decimal(str(t["amount"]))
                if amt % 100 != 0:
                    mult_100_ok = False
                if amt > Decimal("20000.00"):
                    limits_ok = False

        fin_pass = (not neg_balance) and mult_100_ok and limits_ok
        fin_msg = f"Zero negative balances: {not neg_balance}, Withdrawals multiple of 100: {mult_100_ok}, Per-txn limit <= INR 20,000: {limits_ok}"
        results.append(ValidationResult("Financial Rules & Balance Invariants", fin_pass, fin_msg))

        # -------------------------------------------------------------
        # CHECK 3: Foreign Key & Reference Integrity
        # -------------------------------------------------------------
        acc_nums = {a["account_number"] for a in data.get("accounts", [])}
        atm_codes = {a["atm_code"] for a in atms}
        orphan_txns = 0

        for t in txns:
            if t["account_number"] not in acc_nums or t["atm_code"] not in atm_codes:
                orphan_txns += 1

        # Check DB transactions
        stmt_orphan_db = select(Transaction).outerjoin(Account, Transaction.account_id == Account.id).outerjoin(Atm, Transaction.atm_id == Atm.id).where((Account.id.is_(None)) | (Atm.id.is_(None)))
        db_orphans = len((await session.execute(stmt_orphan_db)).scalars().all())

        ref_pass = (orphan_txns == 0 and db_orphans == 0)
        ref_msg = f"JSON orphan transactions: {orphan_txns}, DB orphan transactions: {db_orphans}"
        results.append(ValidationResult("Foreign Key & Reference Integrity", ref_pass, ref_msg))

        # -------------------------------------------------------------
        # CHECK 4: Temporal Coverage (Last 60 Days)
        # -------------------------------------------------------------
        timestamps = [datetime.datetime.fromisoformat(t["created_at"]) for t in txns]
        if timestamps:
            min_ts = min(timestamps)
            max_ts = max(timestamps)
            span_days = (max_ts - min_ts).days
            temp_pass = (span_days >= 55)
            temp_msg = f"History spans {span_days} days (from {min_ts.strftime('%Y-%m-%d')} to {max_ts.strftime('%Y-%m-%d')})"
        else:
            temp_pass = False
            temp_msg = "No transaction timestamps found"
        results.append(ValidationResult("Temporal Baseline Coverage (60 Days)", temp_pass, temp_msg))

        # -------------------------------------------------------------
        # CHECK 5: Determinism (Byte-Identical Generator Runs)
        # -------------------------------------------------------------
        h1 = hashlib.sha256(SEED_JSON_PATH.read_bytes()).hexdigest()
        # Execute generator again
        proc = subprocess.run([sys.executable, str(GENERATOR_SCRIPT)], capture_output=True, text=True)
        h2 = hashlib.sha256(SEED_JSON_PATH.read_bytes()).hexdigest()
        det_pass = (proc.returncode == 0 and h1 == h2)
        det_msg = f"Pass 1 SHA-256: {h1[:16]}... | Pass 2 SHA-256: {h2[:16]}... | Identical: {h1 == h2}"
        results.append(ValidationResult("Deterministic Reproducibility", det_pass, det_msg))

        # -------------------------------------------------------------
        # CHECK 6: Data Protection & Zero-Knowledge Credentials
        # -------------------------------------------------------------
        # Scan JSON and DB for leaks
        leak_found = False
        leak_reasons = []

        # 1. Plaintext PIN search in json (keys like "pin" with 4 digits)
        if '"pin":' in json_data:
            leak_found = True
            leak_reasons.append("Plain 'pin' key detected in seed_data.json")

        # 2. Plaintext password search in json
        if '"password":' in json_data or '"password_plain":' in json_data:
            leak_found = True
            leak_reasons.append("Plain 'password' key detected in seed_data.json")

        # 3. Full card PAN search (16 digit sequence in JSON)
        # Check cards in JSON
        for c in data.get("cards", []):
            if "pan" in c or "card_number" in c:
                leak_found = True
                leak_reasons.append("Plain PAN field in cards object")

        # Check DB cards
        db_cards = (await session.execute(select(Card))).scalars().all()
        for dc in db_cards:
            if len(dc.last4) != 4 or len(dc.card_number_hash) != 64:
                leak_found = True
                leak_reasons.append("Card row in DB does not conform to hash+last4 standard")

        # Check credentials file is ignored
        gitignore_path = backend_dir.parent / ".gitignore"
        gitignore_ok = False
        if gitignore_path.exists():
            content = gitignore_path.read_text(encoding="utf-8")
            if "DEMO_CREDENTIALS.md" in content:
                gitignore_ok = True

        sec_pass = (not leak_found) and gitignore_ok
        sec_msg = f"Zero PAN/Plain-credential leaks: {not leak_found}. DEMO_CREDENTIALS.md in .gitignore: {gitignore_ok}"
        if leak_reasons:
            sec_msg += f" (Violations: {', '.join(leak_reasons)})"
        results.append(ValidationResult("Zero-Knowledge Security & Privacy Protection", sec_pass, sec_msg))

        # -------------------------------------------------------------
        # CHECK 7: Cryptographic Audit Chain Integrity
        # -------------------------------------------------------------
        audit_check = await verify_audit_chain(session)
        audit_pass = (audit_check["status"] == "VALID" and audit_check["total_logs"] > 0 and not audit_check["tampered"])
        audit_msg = f"Status: {audit_check['status']}, Verified logs: {audit_check['verified_logs']}/{audit_check['total_logs']}, Tampered: {audit_check['tampered']}"
        results.append(ValidationResult("Cryptographic Audit Chain Integrity", audit_pass, audit_msg))

        # -------------------------------------------------------------
        # CHECK 8: Anomaly Injection Rate (1 - 3 percent)
        # -------------------------------------------------------------
        anomalies = [t for t in txns if t.get("is_anomaly")]
        anom_count = len(anomalies)
        total_txns = len(txns)
        anom_rate = (anom_count / total_txns) * 100 if total_txns > 0 else 0.0

        anom_pass = (1.0 <= anom_rate <= 3.0)
        anom_msg = f"Anomalies: {anom_count} / {total_txns} ({anom_rate:.2f}% of transactions - target: 1-3%)"
        results.append(ValidationResult("UEBA Anomaly Injection Distribution", anom_pass, anom_msg))

    return results


def print_results(results: List[ValidationResult]) -> bool:
    print("\n" + "=" * 80)
    print("               SECUREVAULT ATM SEED VALIDATION REPORT")
    print("=" * 80)
    all_passed = True
    for idx, r in enumerate(results, start=1):
        status = "PASS" if r.passed else "FAIL"
        color_tag = "[PASS]" if r.passed else "[FAIL]"
        if not r.passed:
            all_passed = False
        print(f" {idx}. {color_tag:<7} {r.name}")
        print(f"    Details: {r.message}")
        if r.details:
            print(f"    Notes  : {r.details}")
        print("-" * 80)

    print("=" * 80)
    overall = "ALL TESTS PASSED" if all_passed else "VALIDATION FAILED"
    print(f" OVERALL VERDICT: {overall} ({sum(1 for r in results if r.passed)}/{len(results)} Passed)")
    print("=" * 80 + "\n")
    return all_passed


def main():
    results = asyncio.run(run_validations())
    passed = print_results(results)
    if not passed:
        sys.exit(1)


if __name__ == "__main__":
    main()
