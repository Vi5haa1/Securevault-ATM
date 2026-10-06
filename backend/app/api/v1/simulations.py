from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete

from app.db.session import get_db
from app.db.models.models import (
    Card, CardStatus, Account, AccountStatus, Atm, AtmStatus,
    AtmSensor, SensorState, Incident, Alert, SecurityEvent, User
)
from app.schemas.simulation import SimulationRequest, SimulationResultResponse
from app.core.deps import require_permission
from app.simulation.runner import SimulationRunner
from app.audit.writer import write_audit_log

router = APIRouter(prefix="/simulations", tags=["Defensive Attack Simulations"])


@router.post("/run", response_model=SimulationResultResponse)
async def run_attack_simulation(
    payload: SimulationRequest,
    current_user: User = Depends(require_permission("soc:simulations")),
    db: AsyncSession = Depends(get_db)
):
    """
    Executes a defensive attack simulation through the genuine internal detection pipeline.
    Simulations are strictly defensive, in-app, fully audited, and flagged is_simulated=True.
    """
    try:
        result = await SimulationRunner.run_simulation(
            db=db,
            simulation_type=payload.simulation_type,
            atm_id=payload.atm_id,
            account_id=payload.account_id,
            intensity=payload.intensity or 1
        )
        await db.commit()
        return SimulationResultResponse(**result)
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/reset-demo")
async def reset_demo_data(
    current_user: User = Depends(require_permission("soc:simulations")),
    db: AsyncSession = Depends(get_db)
):
    """
    Resets demo artifacts:
    - Unlocks locked cards and accounts
    - Resets ATMs to ONLINE and sensors to NORMAL
    - Cleans up simulated incidents, alerts, and events
    """
    # Unlock cards
    await db.execute(update(Card).values(status=CardStatus.ACTIVE, pin_failed_attempts=0))

    # Unlock accounts
    await db.execute(update(Account).values(status=AccountStatus.ACTIVE))

    # Reset ATMs firmware, certs, and operational state
    await db.execute(
        update(Atm).values(
            status=AtmStatus.ONLINE,
            security_status="SECURE",
            under_attack=False,
            risk_score=5,
            secure_boot_enabled=True,
            certificate_status="VALID",
            firmware_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
    )

    # Reset certificates
    from app.db.models.models import Certificate
    await db.execute(update(Certificate).values(status="VALID", revocation_reason=None))

    # Reset sensors
    await db.execute(update(AtmSensor).values(state=SensorState.NORMAL))

    # Reset EMV ATC cache
    from app.services.emv import EmvChipSimulator
    EmvChipSimulator.reset_atc_cache()

    # Delete simulated incidents, alerts, security events
    await db.execute(delete(Incident).where(Incident.is_simulated == True))
    await db.execute(delete(SecurityEvent).where(SecurityEvent.is_simulated == True))

    await write_audit_log(
        db=db,
        action="DEMO_DATA_RESET",
        resource_type="SYSTEM",
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        payload={"message": "All simulated locks, incidents and tamper states reset to normal."}
    )

    await db.commit()
    return {"status": "SUCCESS", "message": "Demo data and simulated locks successfully reset."}
