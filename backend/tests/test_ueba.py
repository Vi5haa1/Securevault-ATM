import pytest
import datetime
from decimal import Decimal
from app.engines.ueba import UEBAEngine, UEBAResult
from app.db.models.models import Atm, AtmStatus, NetworkStatus

@pytest.mark.asyncio
async def test_ueba_normal_transaction(db_session):
    atm = Atm(
        id=1,
        atm_code="SV-ATM-CHE-101",
        city="Chennai",
        address="Mount Road",
        latitude=Decimal("13.0827"),
        longitude=Decimal("80.2707"),
        status=AtmStatus.ONLINE,
        network_status=NetworkStatus.CONNECTED
    )
    normal_time = datetime.datetime(2026, 10, 1, 14, 0, 0, tzinfo=datetime.timezone.utc)
    
    result = await UEBAEngine.evaluate_transaction_behavior(
        db=db_session,
        customer_id=1,
        atm=atm,
        amount=Decimal("3000.00"),
        device_fingerprint="ATM-CLIENT-DEVICE-01",
        txn_timestamp=normal_time
    )
    assert isinstance(result, UEBAResult)
    assert result.anomaly_score < 50
    assert result.classification in ["NORMAL", "LOW"]
    assert "explanation" in result.to_dict()

@pytest.mark.asyncio
async def test_ueba_highly_anomalous_transaction(db_session):
    atm = Atm(
        id=2,
        atm_code="SV-ATM-KOL-999",
        city="Kolkata",
        address="Park Street",
        latitude=Decimal("22.55"),
        longitude=Decimal("88.35"),
        status=AtmStatus.ONLINE,
        network_status=NetworkStatus.CONNECTED
    )
    anom_time = datetime.datetime(2026, 10, 1, 3, 12, 0, tzinfo=datetime.timezone.utc)
    
    result = await UEBAEngine.evaluate_transaction_behavior(
        db=db_session,
        customer_id=1,
        atm=atm,
        amount=Decimal("95000.00"),
        device_fingerprint="UNKNOWN_ROGUE_DEVICE",
        txn_timestamp=anom_time
    )
    assert result.anomaly_score >= 60
    assert result.classification in ["ANOMALOUS", "HIGHLY_ANOMALOUS"]
    assert len(result.explanation) > 10
