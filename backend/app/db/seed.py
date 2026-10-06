import random
import datetime
from decimal import Decimal
from typing import List
from faker import Faker
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.db.models.models import (
    User, Customer, Account, Card, Atm, AtmCashInventory, AtmSensor,
    BehaviorProfile, Transaction, SecurityPolicy, UserRole,
    AccountType, AccountStatus, CardStatus, AtmStatus, NetworkStatus,
    SensorType, SensorState, TransactionType, TransactionStatus, RiskLevel,
    Certificate, HsmKey, KeyUsageAudit, Incident, IncidentAction, IncidentNote,
    Alert, AlertStatus, SecurityEvent, SeverityLevel, IncidentStatus, Notification
)
from app.core.security import hash_password, hash_pin, hash_card_number
from app.services.crypto_vault import PkiService, HsmKeyVault, CryptoVault
from app.audit.writer import write_audit_log

fake = Faker()
Faker.seed(42)
random.seed(42)


# Realistic Indian Metropolitan ATM Locations
ATM_SEED_DATA = [
    # Chennai (5)
    {"code": "SV-ATM-CHE-101", "city": "Chennai", "addr": "Anna Salai, T. Nagar", "lat": 13.0418, "lng": 80.2341, "status": AtmStatus.ONLINE},
    {"code": "SV-ATM-CHE-102", "city": "Chennai", "addr": "Velachery Main Road", "lat": 12.9750, "lng": 80.2206, "status": AtmStatus.ONLINE},
    {"code": "SV-ATM-CHE-103", "city": "Chennai", "addr": "Poonamallee High Road, Kilpauk", "lat": 13.0805, "lng": 80.2452, "status": AtmStatus.ONLINE},
    {"code": "SV-ATM-CHE-104", "city": "Chennai", "addr": "OMR IT Corridor, Sholinganallur", "lat": 12.8996, "lng": 80.2279, "status": AtmStatus.ONLINE},
    {"code": "SV-ATM-CHE-105", "city": "Chennai", "addr": "Adyar Gandhi Nagar", "lat": 13.0067, "lng": 80.2570, "status": AtmStatus.MAINTENANCE},

    # Bangalore (4)
    {"code": "SV-ATM-BLR-201", "city": "Bangalore", "addr": "100 Feet Rd, Indiranagar", "lat": 12.9784, "lng": 77.6408, "status": AtmStatus.ONLINE},
    {"code": "SV-ATM-BLR-202", "city": "Bangalore", "addr": "Koramangala 5th Block", "lat": 12.9352, "lng": 77.6245, "status": AtmStatus.ONLINE},
    {"code": "SV-ATM-BLR-203", "city": "Bangalore", "addr": "Outer Ring Road, Bellandur", "lat": 12.9260, "lng": 77.6762, "status": AtmStatus.ONLINE},
    {"code": "SV-ATM-BLR-204", "city": "Bangalore", "addr": "Whitefield Main Rd", "lat": 12.9698, "lng": 77.7499, "status": AtmStatus.OFFLINE},

    # Mumbai (4)
    {"code": "SV-ATM-BOM-301", "city": "Mumbai", "addr": "BKC Bandra Kurla Complex", "lat": 19.0662, "lng": 72.8687, "status": AtmStatus.ONLINE},
    {"code": "SV-ATM-BOM-302", "city": "Mumbai", "addr": "Nariman Point, Marine Drive", "lat": 18.9256, "lng": 72.8242, "status": AtmStatus.ONLINE},
    {"code": "SV-ATM-BOM-303", "city": "Mumbai", "addr": "Linking Road, Bandra West", "lat": 19.0596, "lng": 72.8335, "status": AtmStatus.ONLINE},
    {"code": "SV-ATM-BOM-304", "city": "Mumbai", "addr": "Powai Hiranandani Gardens", "lat": 19.1176, "lng": 72.9060, "status": AtmStatus.ONLINE},

    # Delhi (3)
    {"code": "SV-ATM-DEL-401", "city": "Delhi", "addr": "Connaught Place, Inner Circle", "lat": 28.6315, "lng": 77.2167, "status": AtmStatus.ONLINE},
    {"code": "SV-ATM-DEL-402", "city": "Delhi", "addr": "Cyber Hub, DLF Phase 2", "lat": 28.4950, "lng": 77.0895, "status": AtmStatus.ONLINE},
    {"code": "SV-ATM-DEL-403", "city": "Delhi", "addr": "Hauz Khas Village", "lat": 28.5494, "lng": 77.1932, "status": AtmStatus.ONLINE},
]


async def seed_database(db: AsyncSession):
    """Populates initial staff, 16 ATMs, 25 customers, inventory, 60 days transaction history, PKI certificates, HSM keys, incidents, and alerts."""
    now_utc = datetime.datetime.now(datetime.timezone.utc)

    # 1. Staff Users
    stmt_check = select(User).where(User.username == "admin")
    res_check = await db.execute(stmt_check)
    admin_user = res_check.scalar_one_or_none()

    if not admin_user:
        staff_defs = [
            ("admin", "admin@securevault.bank", "+919876543210", "Admin@1234", UserRole.SUPER_ADMIN),
            ("bankadmin", "bankadmin@securevault.bank", "+919876543211", "BankAdmin@1234", UserRole.BANK_ADMIN),
            ("analyst1", "analyst1@securevault.bank", "+919876543212", "Analyst@1234", UserRole.SECURITY_ANALYST),
            ("analyst2", "analyst2@securevault.bank", "+919876543213", "Analyst@1234", UserRole.SECURITY_ANALYST),
            ("operator1", "operator1@securevault.bank", "+919876543214", "Operator@1234", UserRole.ATM_OPERATOR),
            ("operator2", "operator2@securevault.bank", "+919876543215", "Operator@1234", UserRole.ATM_OPERATOR),
        ]
        for uname, email, phone, pwd, role in staff_defs:
            user = User(
                username=uname,
                email=email,
                phone=phone,
                password_hash=hash_password(pwd),
                role=role,
                enabled=True,
                mfa_enabled=False
            )
            db.add(user)

        # 2. Security Policies
        policies = [
            ("RISK_WEIGHTS", {"large_amount": 20, "new_location": 25, "unusual_time": 10, "velocity": 20, "new_device": 15, "failed_auth": 10}, "Dynamic weights for risk scoring factors"),
            ("RISK_THRESHOLDS", {"low_max": 30, "medium_max": 60, "high_max": 80, "critical_min": 81}, "Risk level classification boundaries"),
            ("ATM_LIMITS", {"default_daily_withdrawal": 40000.0, "default_per_txn": 20000.0}, "Default withdrawal limits"),
            ("AUTH_POLICIES", {"max_pin_attempts": 5, "session_timeout_seconds": 60}, "Lockout and timeout thresholds")
        ]
        for key, val, desc in policies:
            db.add(SecurityPolicy(key=key, value=val, description=desc))

        # 3. ATMs, Inventories, and Sensors
        created_atms: List[Atm] = []
        for item in ATM_SEED_DATA:
            cash_amt = Decimal("1200000.00") if item["status"] != AtmStatus.MAINTENANCE else Decimal("45000.00")
            atm = Atm(
                atm_code=item["code"],
                city=item["city"],
                address=item["addr"],
                latitude=Decimal(str(item["lat"])),
                longitude=Decimal(str(item["lng"])),
                status=item["status"],
                network_status=NetworkStatus.CONNECTED if item["status"] != AtmStatus.OFFLINE else NetworkStatus.DISCONNECTED,
                cash_total=cash_amt,
                low_cash_threshold=Decimal("100000.00"),
                security_status="SECURE" if item["status"] != AtmStatus.MAINTENANCE else "LOW_CASH_WARNING",
                firmware_version="SV-ATM-FW-3.4.1",
                firmware_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                secure_boot_enabled=True,
                risk_score=5 if item["status"] == AtmStatus.ONLINE else (45 if item["status"] == AtmStatus.MAINTENANCE else 20),
                latency_ms=random.randint(18, 35),
                cpu_usage=random.randint(15, 30),
                memory_usage=random.randint(28, 48),
                disk_usage=random.randint(40, 52),
                under_attack=False,
                last_heartbeat=now_utc
            )
            db.add(atm)
            await db.flush()
            created_atms.append(atm)

            # Cash Denomination Inventory
            multiplier = 1 if item["status"] != AtmStatus.MAINTENANCE else 0.05
            db.add(AtmCashInventory(atm_id=atm.id, denomination=2000, note_count=int(200 * multiplier)))
            db.add(AtmCashInventory(atm_id=atm.id, denomination=500, note_count=int(1000 * multiplier)))
            db.add(AtmCashInventory(atm_id=atm.id, denomination=200, note_count=int(1000 * multiplier)))
            db.add(AtmCashInventory(atm_id=atm.id, denomination=100, note_count=int(1000 * multiplier)))

            # Sensors
            for st in SensorType:
                state = SensorState.NORMAL
                if item["status"] == AtmStatus.OFFLINE and st == SensorType.NETWORK:
                    state = SensorState.ALERT
                db.add(AtmSensor(atm_id=atm.id, sensor_type=st, state=state))

        # 4. 25 Customers, Accounts, Cards, Profiles, and 60 days history
        demo_cards = [
            ("rahul.sharma", "Rahul Sharma", "Mumbai", "4826", "4532015893024826"),
            ("priya.patel", "Priya Patel", "Bangalore", "7391", "5241890248107391"),
            ("aravind.swamy", "Aravind Swamy", "Chennai", "9182", "4111222233339182"),
            ("ananya.sen", "Ananya Sen", "Delhi", "6254", "4000123456786254"),
        ]

        for i in range(25):
            if i < len(demo_cards):
                uname, fname, hcity, pin, card_num = demo_cards[i]
            else:
                fname = fake.name()
                uname = fname.lower().replace(" ", ".") + str(random.randint(10, 99))
                hcity = random.choice(["Chennai", "Bangalore", "Mumbai", "Delhi"])
                pin = f"{random.randint(1000, 9999)}"
                card_num = f"4{random.randint(100000000000000, 999999999999999)}"

            u = User(
                username=uname,
                email=f"{uname}@example.com",
                phone=f"+9198{random.randint(10000000, 99999999)}",
                password_hash=hash_password(f"Pass@{pin}"),
                role=UserRole.CUSTOMER,
                enabled=True
            )
            db.add(u)
            await db.flush()

            cust = Customer(user_id=u.id, full_name=fname, home_city=hcity)
            db.add(cust)
            await db.flush()

            acc_num = f"SV10000000{i:02d}"
            account = Account(
                customer_id=cust.id,
                account_number=acc_num,
                account_type=AccountType.SAVINGS,
                balance=Decimal(f"{random.randint(25000, 80000)}.00"),
                currency="INR",
                daily_limit=Decimal("40000.00"),
                per_txn_limit=Decimal("20000.00"),
                status=AccountStatus.ACTIVE
            )
            db.add(account)
            await db.flush()

            card = Card(
                account_id=account.id,
                card_number_hash=hash_card_number(card_num),
                last4=card_num[-4:],
                pin_hash=hash_pin(pin),
                status=CardStatus.ACTIVE,
                expiry="12/28"
            )
            db.add(card)

            profile = BehaviorProfile(
                customer_id=cust.id,
                avg_withdrawal=Decimal(f"{random.randint(2000, 4000)}.00"),
                std_withdrawal=Decimal("1200.00"),
                typical_min=Decimal("500.00"),
                typical_max=Decimal("6000.00"),
                typical_start_hour=8,
                typical_end_hour=21,
                typical_cities=[hcity],
                txn_per_week_avg=Decimal("3.50")
            )
            db.add(profile)

            # Historical Transactions
            matching_atms = [a for a in created_atms if a.city == hcity]
            primary_atm = matching_atms[0] if matching_atms else created_atms[0]

            for day in range(1, 45, random.randint(2, 4)):
                txn_time = now_utc - datetime.timedelta(days=day, hours=random.randint(9, 19))
                t_amt = Decimal(f"{random.choice([500, 1000, 2000, 3000, 4000, 5000])}.00")
                db.add(Transaction(
                    account_id=account.id,
                    atm_id=primary_atm.id,
                    type=TransactionType.WITHDRAWAL,
                    amount=t_amt,
                    status=TransactionStatus.APPROVED,
                    risk_score=random.randint(5, 20),
                    risk_level=RiskLevel.LOW,
                    device_fingerprint="web-kiosk-trusted",
                    idempotency_key=f"SEED-HIST-{cust.id}-{day}",
                    receipt_no=f"REC-HIST-{cust.id}-{day}",
                    is_simulated=False,
                    created_at=txn_time
                ))

        await db.commit()

        await write_audit_log(
            db=db,
            action="DATABASE_SEEDED",
            resource_type="SYSTEM",
            actor_id="SYSTEM_INIT",
            actor_role="SUPER_ADMIN",
            payload={"staff_count": 6, "customer_count": 25, "atm_count": 16}
        )
        await db.commit()

    # 5. Backfill X.509 PKI Certificates if missing
    stmt_cert_check = select(Certificate).limit(1)
    res_cert_check = await db.execute(stmt_cert_check)
    if not res_cert_check.scalar_one_or_none():
        # Root CA Certificate
        ca_cert = Certificate(
            cert_id="CERT-ROOT-CA-01",
            subject="CN=SecureVault Internal ATM Root CA, O=SecureVault ATM Banking Corp, C=IN",
            issuer="CN=SecureVault Internal ATM Root CA, O=SecureVault ATM Banking Corp, C=IN",
            serial_number="1000000000000001",
            fingerprint="9a8f4c2e6d1b3a5f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f",
            valid_from=now_utc - datetime.timedelta(days=180),
            valid_until=now_utc + datetime.timedelta(days=3650),
            status="VALID",
            public_key_pem="-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIU...\n-----END CERTIFICATE-----",
            atm_id=None
        )
        db.add(ca_cert)
        await db.flush()

        # Generate genuine cryptographic certificates for all 16 ATMs
        stmt_all_atms = select(Atm).order_by(Atm.id)
        res_all_atms = await db.execute(stmt_all_atms)
        all_atms = res_all_atms.scalars().all()

        for a in all_atms:
            try:
                await PkiService.issue_atm_certificate(db, a.atm_code, a.id)
            except Exception:
                pass
        await db.commit()

    # 6. Backfill HSM Key Vault Keys if missing
    stmt_key_check = select(HsmKey).limit(1)
    res_key_check = await db.execute(stmt_key_check)
    if not res_key_check.scalar_one_or_none():
        key_purposes = [
            ("TRANSACTION_ENCRYPTION", "AES-256-GCM"),
            ("PIN_BLOCK_ENCRYPTION", "AES-256-CBC"),
            ("MESSAGE_AUTHENTICATION", "HMAC-SHA256"),
            ("FIRMWARE_SIGNING", "Ed25519"),
            ("DATABASE_AT_REST", "AES-256-GCM"),
        ]
        for purpose, algo in key_purposes:
            await HsmKeyVault.get_or_create_key(db, purpose, algo)

        sample_audits = [
            ("KEY-TRANSACTION_ENCRYPTION-V1", "ENCRYPT", "ATM_TRANSACTION_PAYLOAD", True),
            ("KEY-TRANSACTION_ENCRYPTION-V1", "DECRYPT", "ATM_TRANSACTION_RESPONSE", True),
            ("KEY-MESSAGE_AUTHENTICATION-V1", "SIGN", "ISO_8583_DE64_MAC", True),
            ("KEY-MESSAGE_AUTHENTICATION-V1", "VERIFY", "ISO_8583_DE64_MAC", True),
            ("KEY-PIN_BLOCK_ENCRYPTION-V1", "ENCRYPT", "ISO_9564_FORMAT_0_BLOCK", True),
            ("KEY-FIRMWARE_SIGNING-V1", "SIGN", "FIRMWARE_MANIFEST_3.4.1", True),
        ]
        for kid, act, res_name, succ in sample_audits:
            db.add(KeyUsageAudit(
                key_id=kid,
                action=act,
                actor="SYSTEM_CRYPTO_ENGINE",
                resource=res_name,
                timestamp=now_utc - datetime.timedelta(minutes=random.randint(5, 120)),
                success=succ
            ))
        await db.commit()

    # 7. Backfill Realistic Baseline Incidents, Alerts & Security Events if missing
    stmt_inc_check = select(Incident).where(Incident.incident_code == "SV-INC-2026-08A01")
    res_inc_check = await db.execute(stmt_inc_check)
    if not res_inc_check.scalar_one_or_none():
        # Fetch analyst user id
        stmt_analyst = select(User).where(User.username == "analyst1")
        res_analyst = await db.execute(stmt_analyst)
        analyst = res_analyst.scalar_one_or_none()
        analyst_id = analyst.id if analyst else 1

        # Fetch ATM #1 and #4
        stmt_atm1 = select(Atm).where(Atm.atm_code == "SV-ATM-CHE-101")
        res_atm1 = await db.execute(stmt_atm1)
        atm1 = res_atm1.scalar_one_or_none()
        atm1_id = atm1.id if atm1 else 1

        stmt_atm4 = select(Atm).where(Atm.atm_code == "SV-ATM-BLR-204")
        res_atm4 = await db.execute(stmt_atm4)
        atm4 = res_atm4.scalar_one_or_none()
        atm4_id = atm4.id if atm4 else 4

        # Incident 1: Credential Stuffing / Brute Force (T1110)
        inc1 = Incident(
            incident_code="SV-INC-2026-08A01",
            severity=SeverityLevel.HIGH,
            threat_type="BRUTE_FORCE",
            atm_id=atm1_id,
            status=IncidentStatus.RESOLVED,
            assigned_analyst_id=analyst_id,
            summary="Multiple sequential failed PIN attempts against card ending in 4826 correlated across 5-minute sliding window.",
            resolved_at=now_utc - datetime.timedelta(days=2),
            is_simulated=False
        )
        db.add(inc1)
        await db.flush()

        db.add(IncidentAction(
            incident_id=inc1.id,
            action_type="CARD_LOCKOUT",
            result="Card 4532015893024826 temporarily locked out after 5 consecutive PIN failures."
        ))
        db.add(IncidentAction(
            incident_id=inc1.id,
            action_type="SOC_NOTIFICATION",
            result="Dispatched high-priority alert to active security analysts."
        ))
        db.add(IncidentNote(
            incident_id=inc1.id,
            author_id=analyst_id,
            text="Analyst investigation verified brute-force behavior. Cardholder was contacted; PIN reset challenge issued via OTP."
        ))

        # Event & Alert 1
        ev1 = SecurityEvent(
            type="AUTH_FAILED_PIN_SPIKE",
            severity=SeverityLevel.HIGH,
            source="ATM_PIN_PAD",
            atm_id=atm1_id,
            user_id=None,
            account_id=1,
            details={"failed_attempts": 5, "window_seconds": 120, "rule": "RULE-SV-001"},
            correlation_key=f"ATM-{atm1_id}-CARD-1",
            mitre_technique="T1110 - Brute Force",
            mitre_tactic="Credential Access",
            incident_id=inc1.id,
            rule_id="RULE-SV-001",
            is_simulated=False
        )
        db.add(ev1)
        await db.flush()

        db.add(Alert(
            event_id=ev1.id,
            severity=SeverityLevel.HIGH,
            title="Threshold Exceeded: 5 Failed PIN Entries",
            message="Card ending in 4826 locked out. SOAR playbook executed.",
            status=AlertStatus.CLOSED
        ))

        # Incident 2: Enclosure Tamper & Vibration Sensor Breach (T1098)
        inc2 = Incident(
            incident_code="SV-INC-2026-08B12",
            severity=SeverityLevel.CRITICAL,
            threat_type="ATM_PHYSICAL_TAMPER",
            atm_id=atm4_id,
            status=IncidentStatus.CONTAINED,
            assigned_analyst_id=analyst_id,
            summary="Physical enclosure tamper sensor and seismic vibration sensor tripped at SV-ATM-BLR-204 (Whitefield Main Rd).",
            resolved_at=None,
            is_simulated=False
        )
        db.add(inc2)
        await db.flush()

        db.add(IncidentAction(
            incident_id=inc2.id,
            action_type="EMERGENCY_LOCKDOWN",
            result="Terminal SV-ATM-BLR-204 shifted to emergency LOCKDOWN mode. Dispenser and card slot locked."
        ))
        db.add(IncidentAction(
            incident_id=inc2.id,
            action_type="CASH_CASSETTE_PURGE",
            result="Cash safe locked and cryptographic audit record committed."
        ))
        db.add(IncidentNote(
            incident_id=inc2.id,
            author_id=analyst_id,
            text="Field service engineer dispatched with physical inspection ticket #FE-8921. Security cameras checked."
        ))

        ev2 = SecurityEvent(
            type="ATM_TAMPER_DETECTED",
            severity=SeverityLevel.CRITICAL,
            source="HARDWARE_SENSORS",
            atm_id=atm4_id,
            details={"sensor": "TAMPER_SEISMIC", "vibration_g": 3.8, "door_state": "OPEN"},
            correlation_key=f"ATM-{atm4_id}-TAMPER",
            mitre_technique="T1098 - Account or Hardware Manipulation",
            mitre_tactic="Defense Evasion",
            incident_id=inc2.id,
            rule_id="RULE-SV-003",
            is_simulated=False
        )
        db.add(ev2)
        await db.flush()

        db.add(Alert(
            event_id=ev2.id,
            severity=SeverityLevel.CRITICAL,
            title="CRITICAL: Seismic Sensor & Safe Door Breach",
            message="Terminal SV-ATM-BLR-204 under physical attack. Immediate containment executed.",
            status=AlertStatus.ACKNOWLEDGED
        ))

        # Incident 3: ISO 8583 Message Authentication Failure (T1565)
        inc3 = Incident(
            incident_code="SV-INC-2026-09C04",
            severity=SeverityLevel.MEDIUM,
            threat_type="MAC_VERIFICATION_FAILURE",
            atm_id=atm1_id,
            status=IncidentStatus.RESOLVED,
            assigned_analyst_id=analyst_id,
            summary="Financial ISO 8583 message rejected: DE 64 Message Authentication Code (MAC) cryptographic checksum verification failed.",
            resolved_at=now_utc - datetime.timedelta(days=1),
            is_simulated=False
        )
        db.add(inc3)
        await db.flush()

        db.add(IncidentAction(
            incident_id=inc3.id,
            action_type="TRANSACTION_REJECTION",
            result="Financial packet dropped. HSM session re-keyed."
        ))

        ev3 = SecurityEvent(
            type="MAC_VERIFICATION_FAILURE",
            severity=SeverityLevel.MEDIUM,
            source="ISO_8583_GATEWAY",
            atm_id=atm1_id,
            details={"mti": "0200", "stan": "921820", "mac_algorithm": "HMAC-SHA256"},
            mitre_technique="T1565 - Data Manipulation",
            mitre_tactic="Impact",
            incident_id=inc3.id,
            rule_id="RULE-SV-005",
            is_simulated=False
        )
        db.add(ev3)
        await db.flush()

        db.add(Alert(
            event_id=ev3.id,
            severity=SeverityLevel.MEDIUM,
            title="ISO 8583 Packet Dropped: Invalid DE 64 MAC",
            message="Packet checksum mismatch. Re-authenticated connection.",
            status=AlertStatus.CLOSED
        ))

        await db.commit()

    # 8. Backfill Notifications for staff
    stmt_notif_check = select(Notification).limit(1)
    res_notif_check = await db.execute(stmt_notif_check)
    if not res_notif_check.scalar_one_or_none():
        stmt_users = select(User).where(User.role.in_([UserRole.SECURITY_ANALYST, UserRole.SUPER_ADMIN, UserRole.ATM_OPERATOR]))
        res_users = await db.execute(stmt_users)
        staff_users = res_users.scalars().all()

        notifications_data = [
            ("Live SOC SIEM Initialized", "SecureVault defensive 10-stage pipeline and telemetry engine active.", SeverityLevel.LOW),
            ("Fleet Integrity Verified", "All 16 ATM nodes connected with valid X.509 certificates and secure boot enabled.", SeverityLevel.LOW),
            ("Security Posture Check", "Automated cryptographic posture evaluated across 9 defense categories: 94% SECURE.", SeverityLevel.MEDIUM),
            ("Incident Briefing", "Incident SV-INC-2026-08B12 contained. Terminal SV-ATM-BLR-204 in emergency lockdown.", SeverityLevel.HIGH),
        ]
        for u in staff_users:
            for title, msg, sev in notifications_data:
                db.add(Notification(
                    user_id=u.id,
                    title=title,
                    message=msg,
                    severity=sev,
                    read=False
                ))
        await db.commit()
