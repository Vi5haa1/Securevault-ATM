import pytest
from decimal import Decimal
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models.models import (
    Customer, BehaviorProfile, Atm, AtmStatus, NetworkStatus, 
    User, UserRole, RiskLevel, Account, Card, CardStatus
)
from app.engines.risk_engine import RiskEngine
from app.core.security import hash_password


@pytest.mark.asyncio
async def test_risk_scoring_normal_transaction(db_session: AsyncSession):
    # Setup Customer
    u = User(username="cust1", email="c1@test.com", phone="12345", password_hash=hash_password("pw"), role=UserRole.CUSTOMER)
    db_session.add(u)
    await db_session.flush()

    cust = Customer(user_id=u.id, full_name="Customer One", home_city="Mumbai")
    db_session.add(cust)
    await db_session.flush()

    profile = BehaviorProfile(
        customer_id=cust.id,
        avg_withdrawal=Decimal("2000.00"),
        std_withdrawal=Decimal("1000.00"),
        typical_min=Decimal("500.00"),
        typical_max=Decimal("5000.00"),
        typical_start_hour=0,  # wide hours for testing
        typical_end_hour=23,
        typical_cities=["Mumbai"],
        txn_per_week_avg=Decimal("3.0")
    )
    db_session.add(profile)

    atm = Atm(
        atm_code="SV-ATM-MUM-1",
        city="Mumbai",
        address="Bandra",
        latitude=Decimal("19.0"),
        longitude=Decimal("72.8"),
        status=AtmStatus.ONLINE,
        network_status=NetworkStatus.CONNECTED
    )
    db_session.add(atm)
    await db_session.commit()

    assessment = await RiskEngine.evaluate_transaction_risk(
        db=db_session,
        customer_id=cust.id,
        atm=atm,
        amount=Decimal("1500.00"),
        device_fingerprint=None
    )

    assert assessment.score <= 30
    assert assessment.level == RiskLevel.LOW
    assert assessment.action == "APPROVE"


@pytest.mark.asyncio
async def test_risk_scoring_anomaly_triggers(db_session: AsyncSession):
    # Setup Customer with Bangalore home city
    u = User(username="cust2", email="c2@test.com", phone="12346", password_hash=hash_password("pw"), role=UserRole.CUSTOMER)
    db_session.add(u)
    await db_session.flush()

    cust = Customer(user_id=u.id, full_name="Customer Two", home_city="Bangalore")
    db_session.add(cust)
    await db_session.flush()

    profile = BehaviorProfile(
        customer_id=cust.id,
        avg_withdrawal=Decimal("1000.00"),
        std_withdrawal=Decimal("500.00"),
        typical_min=Decimal("500.00"),
        typical_max=Decimal("3000.00"),
        typical_start_hour=9,
        typical_end_hour=18,
        typical_cities=["Bangalore"],
        txn_per_week_avg=Decimal("2.0")
    )
    db_session.add(profile)

    # ATM in Delhi (New Location: +25)
    atm = Atm(
        atm_code="SV-ATM-DEL-99",
        city="Delhi",
        address="Connaught Place",
        latitude=Decimal("28.6"),
        longitude=Decimal("77.2"),
        status=AtmStatus.ONLINE,
        network_status=NetworkStatus.CONNECTED
    )
    acc = Account(customer_id=cust.id, account_number="SV2222", balance=Decimal("100000.00"))
    db_session.add(acc)
    await db_session.flush()

    card = Card(
        account_id=acc.id,
        card_number_hash="test_card_hash",
        last4="9999",
        pin_hash="hash",
        status=CardStatus.ACTIVE,
        pin_failed_attempts=1,  # +10 points -> score 70 -> HIGH
        expiry="12/28"
    )
    db_session.add(card)
    await db_session.commit()

    # Amount: 40000 (> 2x typical_max: +20)
    # New Device: +15
    # Total Score: at least 25 + 20 + 15 = 60 (HIGH or CRITICAL)
    assessment = await RiskEngine.evaluate_transaction_risk(
        db=db_session,
        customer_id=cust.id,
        atm=atm,
        amount=Decimal("40000.00"),
        device_fingerprint="unknown-hw-token-999"
    )

    assert assessment.score >= 60
    assert assessment.level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert any(f["factor_name"] == "UNUSUAL_LOCATION" and f["triggered"] for f in assessment.factors)
    assert any(f["factor_name"] == "LARGE_AMOUNT_DEVIATION" and f["triggered"] for f in assessment.factors)
