import pytest
import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from app.audit.writer import write_audit_log
from app.audit.verifier import verify_audit_chain
from app.db.models.models import AuditLog


@pytest.mark.asyncio
async def test_audit_chain_validity(db_session: AsyncSession):
    # Empty chain verification
    result = await verify_audit_chain(db_session)
    assert result["status"] == "VALID"
    assert result["tampered"] is False

    # Append 3 logs
    await write_audit_log(
        db=db_session,
        action="USER_LOGIN",
        resource_type="USER",
        actor_id="user1",
        payload={"ip": "127.0.0.1"}
    )
    await write_audit_log(
        db=db_session,
        action="WITHDRAWAL",
        resource_type="ACCOUNT",
        actor_id="user1",
        payload={"amount": "2000.00"}
    )
    await write_audit_log(
        db=db_session,
        action="PIN_CHANGE",
        resource_type="CARD",
        actor_id="user1",
        payload={"card_last4": "4826"}
    )
    await db_session.commit()

    # Verify chain
    result = await verify_audit_chain(db_session)
    assert result["status"] == "VALID"
    assert result["total_logs"] == 3
    assert result["verified_logs"] == 3
    assert result["tampered"] is False


@pytest.mark.asyncio
async def test_audit_chain_detects_tampering(db_session: AsyncSession):
    log1 = await write_audit_log(
        db=db_session,
        action="INITIAL_DEPOSIT",
        resource_type="ACCOUNT",
        actor_id="user1",
        payload={"amount": "10000.00"}
    )
    log2 = await write_audit_log(
        db=db_session,
        action="WITHDRAWAL",
        resource_type="ACCOUNT",
        actor_id="user1",
        payload={"amount": "1000.00"}
    )
    await db_session.commit()

    # Directly tamper with log1 payload without recalculating cryptographic hash
    log1.action = "TAMPERED_ACTION_UNAUTHORIZED"
    await db_session.commit()

    # Verify should detect broken link
    verify_res = await verify_audit_chain(db_session)
    assert verify_res["status"] == "BROKEN"
    assert verify_res["tampered"] is True
    assert verify_res["broken_sequence_no"] == 1
    assert "tampering detected" in verify_res["details"].lower()
