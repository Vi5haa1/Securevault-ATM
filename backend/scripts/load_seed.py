#!/usr/bin/env python3
"""
SecureVault ATM: Database Seed Loader
Loads synthetic dataset from backend/data/seed_data.json into the real database
using existing SQLAlchemy models and async session.
Operates within a single atomic transaction.
Supports idempotency and optional --reset flag.
"""

import sys
import os
import json
import asyncio
import datetime
from decimal import Decimal
from pathlib import Path
from typing import Dict, Any, Optional, List

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from sqlalchemy import select, delete, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import AsyncSessionLocal, engine
from app.db.base import Base
from app.db.models.models import (
    User, Customer, Account, Card, Atm, AtmCashInventory, AtmSensor,
    BehaviorProfile, Transaction, SecurityPolicy, DetectionRule, ThreatIndicator,
    Certificate, TrustedDevice, AuditLog, UserRole, AccountType, AccountStatus,
    CardStatus, AtmStatus, NetworkStatus, SensorType, SensorState,
    TransactionType, TransactionStatus, RiskLevel, SeverityLevel
)
from app.audit.writer import write_audit_log
from app.audit.verifier import verify_audit_chain

SEED_JSON_PATH = backend_dir / "data" / "seed_data.json"


async def load_seed_data(reset: bool = False, confirm_yes: bool = False) -> Dict[str, int]:
    """
    Loads backend/data/seed_data.json into the active database.
    """
    if not SEED_JSON_PATH.exists():
        raise FileNotFoundError(f"Seed file not found at {SEED_JSON_PATH}. Run seed_faker.py first.")

    with open(SEED_JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    if reset and not confirm_yes:
        resp = input("[!] WARNING: --reset will clear seeded tables. Type 'yes' to proceed: ")
        if resp.strip().lower() != "yes":
            print("[-] Reset cancelled by user.")
            return {}

    inserted_counts = {
        "staff_users": 0,
        "customers": 0,
        "accounts": 0,
        "cards": 0,
        "devices": 0,
        "atms": 0,
        "atm_inventory": 0,
        "atm_sensors": 0,
        "certificates": 0,
        "transactions": 0,
        "behavior_profiles": 0,
        "detection_rules": 0,
        "policies": 0,
        "threat_indicators": 0,
        "audit_logs": 0,
    }

    # Ensure tables exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        async with session.begin():
            if reset:
                print("[*] Resetting database tables in foreign-key dependency order...")
                # Reverse foreign-key order
                await session.execute(delete(AuditLog))
                await session.execute(delete(Transaction))
                await session.execute(delete(BehaviorProfile))
                await session.execute(delete(Card))
                await session.execute(delete(TrustedDevice))
                await session.execute(delete(Account))
                await session.execute(delete(Customer))
                await session.execute(delete(AtmSensor))
                await session.execute(delete(AtmCashInventory))
                await session.execute(delete(Certificate))
                await session.execute(delete(Atm))
                await session.execute(delete(ThreatIndicator))
                await session.execute(delete(DetectionRule))
                await session.execute(delete(SecurityPolicy))
                await session.execute(delete(User))
                await session.flush()
                print("[+] Tables reset successfully.")

            # 1. Security Policies
            print("[*] Seeding security policies...")
            for pol in data.get("policies", []):
                stmt = select(SecurityPolicy).where(SecurityPolicy.key == pol["key"])
                res = await session.execute(stmt)
                existing = res.scalar_one_or_none()
                if not existing:
                    session.add(SecurityPolicy(
                        key=pol["key"],
                        value=pol["value"],
                        description=pol["description"]
                    ))
                    inserted_counts["policies"] += 1

            # 2. Detection Rules
            print("[*] Seeding detection rules...")
            for r in data.get("detection_rules", []):
                stmt = select(DetectionRule).where(DetectionRule.rule_id == r["rule_id"])
                res = await session.execute(stmt)
                existing = res.scalar_one_or_none()
                if not existing:
                    session.add(DetectionRule(
                        rule_id=r["rule_id"],
                        name=r["name"],
                        description=r["description"],
                        enabled=r["enabled"],
                        severity=SeverityLevel[r["severity"]],
                        event_types=r["event_types"],
                        conditions=r["conditions"],
                        actions=r["actions"],
                        cooldown_seconds=r["cooldown_seconds"],
                        mitre_tactic=r["mitre_tactic"],
                        mitre_technique=r["mitre_technique"],
                    ))
                    inserted_counts["detection_rules"] += 1

            # 3. Threat Indicators
            print("[*] Seeding threat intelligence indicators...")
            for ti in data.get("threat_indicators", []):
                stmt = select(ThreatIndicator).where(ThreatIndicator.value == ti["value"])
                res = await session.execute(stmt)
                existing = res.scalar_one_or_none()
                if not existing:
                    session.add(ThreatIndicator(
                        indicator_type=ti["indicator_type"],
                        value=ti["value"],
                        threat_category=ti["threat_category"],
                        confidence=ti["confidence"],
                        severity=SeverityLevel[ti["severity"]],
                        tags=ti["tags"],
                        is_active=True
                    ))
                    inserted_counts["threat_indicators"] += 1

            # 4. Staff Users
            print("[*] Seeding staff users...")
            for s in data.get("staff_users", []):
                stmt = select(User).where(User.username == s["username"])
                res = await session.execute(stmt)
                existing = res.scalar_one_or_none()
                if not existing:
                    session.add(User(
                        username=s["username"],
                        email=s["email"],
                        phone=s["phone"],
                        password_hash=s["password_hash"],
                        role=UserRole[s["role"]],
                        enabled=s.get("enabled", True),
                        locked=s.get("locked", False),
                        mfa_enabled=s.get("mfa_enabled", False),
                    ))
                    inserted_counts["staff_users"] += 1
            await session.flush()

            # 5. ATMs, Inventories, Sensors
            print("[*] Seeding ATM nodes, cash inventory, and hardware sensors...")
            atm_map: Dict[str, int] = {}
            for a in data.get("atms", []):
                stmt = select(Atm).where(Atm.atm_code == a["atm_code"])
                res = await session.execute(stmt)
                existing = res.scalar_one_or_none()
                if not existing:
                    atm_obj = Atm(
                        atm_code=a["atm_code"],
                        city=a["city"],
                        address=a["address"],
                        latitude=Decimal(str(a["latitude"])),
                        longitude=Decimal(str(a["longitude"])),
                        status=AtmStatus[a["status"]],
                        network_status=NetworkStatus[a["network_status"]],
                        cash_total=Decimal(str(a["cash_total"])),
                        low_cash_threshold=Decimal(str(a["low_cash_threshold"])),
                        security_status=a.get("security_status", "SECURE"),
                        firmware_version=a.get("firmware_version", "SV-ATM-FW-3.4.1"),
                        firmware_hash=a.get("firmware_hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                        secure_boot_enabled=a.get("secure_boot_enabled", True),
                        certificate_id=a.get("certificate_id"),
                        certificate_status=a.get("certificate_status", "VALID"),
                        risk_score=a.get("risk_score", 5),
                        latency_ms=a.get("latency_ms", 24),
                        cpu_usage=a.get("cpu_usage", 18),
                        memory_usage=a.get("memory_usage", 32),
                        disk_usage=a.get("disk_usage", 45),
                        under_attack=a.get("under_attack", False),
                        last_heartbeat=datetime.datetime.fromisoformat(a["last_heartbeat"]),
                    )
                    session.add(atm_obj)
                    await session.flush()
                    atm_map[a["atm_code"]] = atm_obj.id
                    inserted_counts["atms"] += 1
                else:
                    atm_map[a["atm_code"]] = existing.id

            # Inventories
            for inv in data.get("atm_inventory", []):
                a_id = atm_map.get(inv["atm_code"])
                if not a_id:
                    continue
                stmt = select(AtmCashInventory).where(
                    AtmCashInventory.atm_id == a_id,
                    AtmCashInventory.denomination == inv["denomination"]
                )
                res = await session.execute(stmt)
                if not res.scalar_one_or_none():
                    session.add(AtmCashInventory(
                        atm_id=a_id,
                        denomination=inv["denomination"],
                        note_count=inv["note_count"]
                    ))
                    inserted_counts["atm_inventory"] += 1

            # Sensors
            for sen in data.get("atm_sensors", []):
                a_id = atm_map.get(sen["atm_code"])
                if not a_id:
                    continue
                stmt = select(AtmSensor).where(
                    AtmSensor.atm_id == a_id,
                    AtmSensor.sensor_type == SensorType[sen["sensor_type"]]
                )
                res = await session.execute(stmt)
                if not res.scalar_one_or_none():
                    session.add(AtmSensor(
                        atm_id=a_id,
                        sensor_type=SensorType[sen["sensor_type"]],
                        state=SensorState[sen["state"]],
                        last_updated=datetime.datetime.fromisoformat(sen["last_updated"]),
                    ))
                    inserted_counts["atm_sensors"] += 1

            # Certificates
            print("[*] Seeding digital certificates...")
            for c in data.get("certificates", []):
                stmt = select(Certificate).where(Certificate.cert_id == c["cert_id"])
                res = await session.execute(stmt)
                if not res.scalar_one_or_none():
                    a_id = atm_map.get(c.get("atm_code")) if c.get("atm_code") else None
                    session.add(Certificate(
                        cert_id=c["cert_id"],
                        subject=c["subject"],
                        issuer=c["issuer"],
                        serial_number=c["serial_number"],
                        fingerprint=c["fingerprint"],
                        valid_from=datetime.datetime.fromisoformat(c["valid_from"]),
                        valid_until=datetime.datetime.fromisoformat(c["valid_until"]),
                        status=c["status"],
                        public_key_pem=c["public_key_pem"],
                        atm_id=a_id,
                    ))
                    inserted_counts["certificates"] += 1

            # 6. Customers, Accounts, Cards, Trusted Devices
            print("[*] Seeding customer identities, bank accounts, cards, and trusted devices...")
            cust_map: Dict[str, int] = {}     # username -> customer.id
            account_map: Dict[str, int] = {}  # account_number -> account.id

            for c in data.get("customers", []):
                stmt_u = select(User).where(User.username == c["username"])
                res_u = await session.execute(stmt_u)
                u = res_u.scalar_one_or_none()
                if not u:
                    u = User(
                        username=c["username"],
                        email=c["email"],
                        phone=c["phone"],
                        password_hash=c["password_hash"],
                        role=UserRole[c["role"]],
                        enabled=c.get("enabled", True),
                    )
                    session.add(u)
                    await session.flush()

                stmt_cust = select(Customer).where(Customer.user_id == u.id)
                res_cust = await session.execute(stmt_cust)
                cust = res_cust.scalar_one_or_none()
                if not cust:
                    cust = Customer(
                        user_id=u.id,
                        full_name=c["full_name"],
                        home_city=c["home_city"],
                    )
                    session.add(cust)
                    await session.flush()
                    inserted_counts["customers"] += 1

                cust_map[c["username"]] = cust.id

            # Accounts
            for acc in data.get("accounts", []):
                stmt_a = select(Account).where(Account.account_number == acc["account_number"])
                res_a = await session.execute(stmt_a)
                existing_acc = res_a.scalar_one_or_none()
                c_id = cust_map.get(acc["username"])
                if not existing_acc and c_id:
                    new_acc = Account(
                        customer_id=c_id,
                        account_number=acc["account_number"],
                        type=AccountType[acc["type"]],
                        balance=Decimal(str(acc["balance"])),
                        currency=acc.get("currency", "INR"),
                        status=AccountStatus[acc["status"]],
                        daily_withdrawal_limit=Decimal(str(acc["daily_withdrawal_limit"])),
                        per_txn_limit=Decimal(str(acc["per_txn_limit"])),
                    )
                    session.add(new_acc)
                    await session.flush()
                    account_map[acc["account_number"]] = new_acc.id
                    inserted_counts["accounts"] += 1
                elif existing_acc:
                    account_map[acc["account_number"]] = existing_acc.id

            # Cards
            for card in data.get("cards", []):
                acc_id = account_map.get(card["account_number"])
                if not acc_id:
                    continue
                stmt_card = select(Card).where(Card.card_number_hash == card["card_number_hash"])
                res_card = await session.execute(stmt_card)
                if not res_card.scalar_one_or_none():
                    session.add(Card(
                        account_id=acc_id,
                        card_number_hash=card["card_number_hash"],
                        last4=card["last4"],
                        pin_hash=card["pin_hash"],
                        status=CardStatus[card["status"]],
                        expiry=card["expiry"],
                    ))
                    inserted_counts["cards"] += 1

            # Trusted Devices
            for dev in data.get("devices", []):
                c_id = cust_map.get(dev["username"])
                if not c_id:
                    continue
                stmt_d = select(TrustedDevice).where(
                    TrustedDevice.customer_id == c_id,
                    TrustedDevice.fingerprint == dev["fingerprint"]
                )
                res_d = await session.execute(stmt_d)
                if not res_d.scalar_one_or_none():
                    session.add(TrustedDevice(
                        customer_id=c_id,
                        fingerprint=dev["fingerprint"],
                        first_seen=datetime.datetime.fromisoformat(dev["first_seen"]),
                        last_seen=datetime.datetime.fromisoformat(dev["last_seen"]),
                        trusted=dev.get("trusted", True),
                    ))
                    inserted_counts["devices"] += 1

            # Behavior Profiles
            print("[*] Seeding behavioral profiles...")
            for bp in data.get("behavior_profiles", []):
                c_id = cust_map.get(bp["username"])
                if not c_id:
                    continue
                stmt_bp = select(BehaviorProfile).where(BehaviorProfile.customer_id == c_id)
                res_bp = await session.execute(stmt_bp)
                if not res_bp.scalar_one_or_none():
                    session.add(BehaviorProfile(
                        customer_id=c_id,
                        avg_withdrawal=Decimal(str(bp["avg_withdrawal"])),
                        std_withdrawal=Decimal(str(bp["std_withdrawal"])),
                        typical_min=Decimal(str(bp["typical_min"])),
                        typical_max=Decimal(str(bp["typical_max"])),
                        typical_start_hour=bp["typical_start_hour"],
                        typical_end_hour=bp["typical_end_hour"],
                        typical_cities=bp["typical_cities"],
                        txn_per_week_avg=Decimal(str(bp["txn_per_week_avg"])),
                        updated_at=datetime.datetime.fromisoformat(bp["updated_at"]),
                    ))
                    inserted_counts["behavior_profiles"] += 1

            # 7. Transactions
            print("[*] Seeding 60-day historical transactions and anomalies...")
            for txn in data.get("transactions", []):
                acc_id = account_map.get(txn["account_number"])
                atm_id = atm_map.get(txn["atm_code"])
                if not acc_id or not atm_id:
                    continue

                stmt_t = select(Transaction).where(Transaction.idempotency_key == txn["idempotency_key"])
                res_t = await session.execute(stmt_t)
                if not res_t.scalar_one_or_none():
                    session.add(Transaction(
                        account_id=acc_id,
                        atm_id=atm_id,
                        type=TransactionType[txn["type"]],
                        amount=Decimal(str(txn["amount"])),
                        status=TransactionStatus[txn["status"]],
                        risk_score=txn["risk_score"],
                        risk_level=RiskLevel[txn["risk_level"]],
                        risk_factors=txn.get("risk_factors"),
                        device_fingerprint=txn.get("device_fingerprint"),
                        ip_address=txn.get("ip_address"),
                        idempotency_key=txn["idempotency_key"],
                        receipt_no=txn["receipt_no"],
                        is_simulated=txn.get("is_simulated", False),
                        created_at=datetime.datetime.fromisoformat(txn["created_at"]),
                    ))
                    inserted_counts["transactions"] += 1

            # 8. Cryptographic Audit Log Chain
            print("[*] Verifying & inserting cryptographic audit chain...")
            # Check existing audit logs
            stmt_audit = select(AuditLog).order_by(AuditLog.sequence_no.desc()).limit(1)
            res_audit = await session.execute(stmt_audit)
            last_audit = res_audit.scalar_one_or_none()

            if last_audit is None:
                # Direct load of pre-calculated genesis audit seed
                for a_item in data.get("audit_seed", []):
                    session.add(AuditLog(
                        sequence_no=a_item["sequence_no"],
                        actor_id=a_item["actor_id"],
                        actor_role=a_item["actor_role"],
                        action=a_item["action"],
                        resource_type=a_item["resource_type"],
                        resource_id=a_item["resource_id"],
                        payload=a_item["payload"],
                        ip_address=a_item["ip_address"],
                        created_at=datetime.datetime.fromisoformat(a_item["created_at"]),
                        prev_hash=a_item["prev_hash"],
                        hash=a_item["hash"],
                    ))
                    inserted_counts["audit_logs"] += 1
            else:
                # Audit chain already active; append an event noting seed load
                pass

        # Verification pass on the audit chain
        audit_res = await verify_audit_chain(session)
        print(f"[+] Audit Log Chain Verification: Status={audit_res['status']}, Verified={audit_res['verified_logs']}/{audit_res['total_logs']}")

    print("\n" + "=" * 55)
    print("      DATABASE SEED LOAD RESULTS")
    print("=" * 55)
    for entity, count in inserted_counts.items():
        print(f" {entity:<25} : {count:>8} records inserted")
    print("=" * 55)
    return inserted_counts


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Load SecureVault ATM seed data into database.")
    parser.add_argument("--reset", action="store_true", help="Clear seeded tables before loading.")
    parser.add_argument("--yes", "-y", action="store_true", help="Confirm reset non-interactively.")
    args = parser.parse_args()

    asyncio.run(load_seed_data(reset=args.reset, confirm_yes=args.yes))


if __name__ == "__main__":
    main()
