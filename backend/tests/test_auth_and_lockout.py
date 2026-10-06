import pytest
from decimal import Decimal
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models.models import (
    User, Customer, Account, Card, Atm, AtmStatus, NetworkStatus,
    UserRole, CardStatus, Incident
)
from app.core.security import hash_password, hash_pin, hash_card_number
from app.engines.threat_detection import ThreatDetectionEngine
from app.services.otp import OtpService


@pytest.mark.asyncio
async def test_card_lockout_after_five_failed_pins(db_session: AsyncSession):
    u = User(username="lockout_user", email="l@test.com", phone="1111", password_hash=hash_password("pw"), role=UserRole.CUSTOMER)
    db_session.add(u)
    await db_session.flush()

    cust = Customer(user_id=u.id, full_name="Lockout Test", home_city="Chennai")
    db_session.add(cust)
    await db_session.flush()

    acc = Account(customer_id=cust.id, account_number="SV9999", balance=Decimal("10000.00"))
    db_session.add(acc)
    await db_session.flush()

    card = Card(
        account_id=acc.id,
        card_number_hash=hash_card_number("4532015893024826"),
        last4="4826",
        pin_hash=hash_pin("4826"),
        status=CardStatus.ACTIVE,
        pin_failed_attempts=0,
        expiry="12/28"
    )
    db_session.add(card)

    atm = Atm(
        atm_code="SV-ATM-TEST",
        city="Chennai",
        address="Test Road",
        latitude=Decimal("13.0"),
        longitude=Decimal("80.0"),
        status=AtmStatus.ONLINE,
        network_status=NetworkStatus.CONNECTED
    )
    db_session.add(atm)
    await db_session.commit()

    # Simulate 4 failed attempts
    for i in range(1, 5):
        locked, inc = await ThreatDetectionEngine.handle_failed_pin(db_session, card, atm)
        assert locked is False
        assert inc is None
        assert card.pin_failed_attempts == i
        assert card.status == CardStatus.ACTIVE

    # 5th attempt: should trigger lockout and incident
    locked, inc = await ThreatDetectionEngine.handle_failed_pin(db_session, card, atm)
    assert locked is True
    assert inc is not None
    assert card.status == CardStatus.LOCKED
    assert inc.threat_type == "BRUTE_FORCE"
    assert "SV-INC" in inc.incident_code


@pytest.mark.asyncio
async def test_otp_challenge_lifecycle(db_session: AsyncSession):
    u = User(username="otp_user", email="otp@test.com", phone="2222", password_hash=hash_password("pw"), role=UserRole.CUSTOMER)
    db_session.add(u)
    await db_session.commit()

    # Create challenge
    challenge_id, plain_code = await OtpService.create_challenge(db_session, u.id)
    assert len(plain_code) == 6
    assert plain_code.isdigit()

    # Wrong code verification
    success, msg = await OtpService.verify_challenge(db_session, challenge_id, "000000")
    assert success is False
    assert "Invalid OTP" in msg

    # Correct code verification
    success, msg = await OtpService.verify_challenge(db_session, challenge_id, plain_code)
    assert success is True
    assert "successfully" in msg

    # Replay consumed code
    success, msg = await OtpService.verify_challenge(db_session, challenge_id, plain_code)
    assert success is False
    assert "already been used" in msg
