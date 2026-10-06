import pytest
from decimal import Decimal
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models.models import (
    User, Customer, Account, Card, Atm, AtmStatus, NetworkStatus, 
    UserRole, CardStatus, SensorType, SensorState
)
from app.core.security import hash_password, hash_pin, hash_card_number
from app.simulation.runner import SimulationRunner


@pytest.mark.asyncio
async def test_all_defensive_simulations(db_session: AsyncSession):
    # Setup test entities
    u = User(username="sim_user", email="sim@test.com", phone="3333", password_hash=hash_password("pw"), role=UserRole.CUSTOMER)
    db_session.add(u)
    await db_session.flush()

    cust = Customer(user_id=u.id, full_name="Sim Customer", home_city="Chennai")
    db_session.add(cust)
    await db_session.flush()

    acc = Account(customer_id=cust.id, account_number="SV1111", balance=Decimal("50000.00"))
    db_session.add(acc)
    await db_session.flush()

    card = Card(
        account_id=acc.id,
        card_number_hash=hash_card_number("4532015893024826"),
        last4="4826",
        pin_hash=hash_pin("4826"),
        status=CardStatus.ACTIVE,
        expiry="12/28"
    )
    db_session.add(card)

    atm = Atm(
        atm_code="SV-ATM-SIM-01",
        city="Chennai",
        address="Sim Center",
        latitude=Decimal("13.0"),
        longitude=Decimal("80.0"),
        status=AtmStatus.ONLINE,
        network_status=NetworkStatus.CONNECTED,
        cash_total=Decimal("500000.00")
    )
    db_session.add(atm)
    await db_session.commit()

    # 1. BRUTE_FORCE
    res_bf = await SimulationRunner.run_simulation(db_session, "BRUTE_FORCE", atm_id=atm.id, account_id=acc.id)
    assert res_bf["threat_detected"] is True
    assert "Brute Force" in res_bf["detection_rule"]
    assert res_bf["incident_code"] is not None

    # 2. ATM_TAMPER
    res_tamper = await SimulationRunner.run_simulation(db_session, "ATM_TAMPER", atm_id=atm.id)
    assert res_tamper["threat_detected"] is True
    assert "Tamper" in res_tamper["detection_rule"]
    assert res_tamper["incident_code"] is not None

    # 3. SUSPICIOUS_TXN
    res_st = await SimulationRunner.run_simulation(db_session, "SUSPICIOUS_TXN", atm_id=atm.id, account_id=acc.id)
    assert res_st["threat_detected"] is True
    assert "Risk Score" in res_st["detection_rule"]

    # 4. API_ABUSE
    res_api = await SimulationRunner.run_simulation(db_session, "API_ABUSE", atm_id=atm.id)
    assert res_api["threat_detected"] is True
    assert "Token Bucket" in res_api["detection_rule"]

    # 5. UNAUTHORIZED_ACCESS
    res_unauth = await SimulationRunner.run_simulation(db_session, "UNAUTHORIZED_ACCESS", atm_id=atm.id)
    assert res_unauth["threat_detected"] is True
    assert "RBAC" in res_unauth["detection_rule"]

    # 6. SESSION_ABUSE
    res_sess = await SimulationRunner.run_simulation(db_session, "SESSION_ABUSE", atm_id=atm.id)
    assert res_sess["threat_detected"] is True
    assert "Token" in res_sess["detection_rule"]
