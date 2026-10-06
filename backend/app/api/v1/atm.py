import datetime
from decimal import Decimal
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.db.models.models import (
    Atm, AtmCashInventory, AtmSensor, AtmStatus, NetworkStatus,
    SensorType, SensorState, User, UserRole
)
from app.schemas.atm import (
    AtmResponse, AtmCreateRequest, CashLoadRequest, 
    AtmStatusUpdateRequest, SensorUpdateRequest
)
from app.core.deps import get_current_user, require_permission, require_roles
from app.engines.threat_detection import ThreatDetectionEngine
from app.audit.writer import write_audit_log

router = APIRouter(prefix="/atm", tags=["ATM Management"])


@router.get("", response_model=List[AtmResponse])
async def list_atms(
    city: Optional[str] = None,
    status_filter: Optional[AtmStatus] = None,
    db: AsyncSession = Depends(get_db)
):
    """Public/Kiosk endpoint: Lists ATMs in the network with current operational status."""
    stmt = select(Atm).options(
        selectinload(Atm.sensors),
        selectinload(Atm.inventories)
    )
    if city:
        stmt = stmt.where(Atm.city == city)
    if status_filter:
        stmt = stmt.where(Atm.status == status_filter)

    result = await db.execute(stmt)
    atms = result.scalars().all()
    return atms


@router.get("/{atm_id}", response_model=AtmResponse)
async def get_atm_details(
    atm_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Returns detailed status, inventory note counts, and real-time sensor states for an ATM."""
    stmt = (
        select(Atm)
        .options(selectinload(Atm.sensors), selectinload(Atm.inventories))
        .where(Atm.id == atm_id)
    )
    res = await db.execute(stmt)
    atm = res.scalar_one_or_none()
    if not atm:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ATM terminal not found.")
    return atm


@router.post("/{atm_id}/cash-load", response_model=AtmResponse)
async def load_cash(
    atm_id: int,
    payload: CashLoadRequest,
    current_user: User = Depends(require_permission("atm:cash_load")),
    db: AsyncSession = Depends(get_db)
):
    """ATM Operator/Admin endpoint: Replenishes cash note inventory."""
    stmt = (
        select(Atm)
        .options(selectinload(Atm.inventories), selectinload(Atm.sensors))
        .where(Atm.id == atm_id)
    )
    res = await db.execute(stmt)
    atm = res.scalar_one_or_none()
    if not atm:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ATM not found.")

    added_total = Decimal("0.00")
    for denom, count in payload.denominations.items():
        if count < 0:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Note count cannot be negative.")
        
        # Find inventory row
        inv = next((i for i in atm.inventories if i.denomination == denom), None)
        if inv:
            inv.note_count += count
        else:
            inv = AtmCashInventory(atm_id=atm.id, denomination=denom, note_count=count)
            db.add(inv)
            atm.inventories.append(inv)
        
        added_total += Decimal(denom * count)

    atm.cash_total += added_total
    
    # If ATM was low cash or out of cash, update status if appropriate
    if atm.status == AtmStatus.MAINTENANCE and atm.cash_total >= atm.low_cash_threshold:
        atm.status = AtmStatus.ONLINE

    await write_audit_log(
        db=db,
        action="ATM_CASH_LOADED",
        resource_type="ATM",
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        resource_id=atm.atm_code,
        payload={"denominations": payload.denominations, "added_total": str(added_total), "new_total": str(atm.cash_total)}
    )

    await db.commit()
    await db.refresh(atm)
    return atm


@router.post("/{atm_id}/status", response_model=AtmResponse)
async def update_atm_status(
    atm_id: int,
    payload: AtmStatusUpdateRequest,
    current_user: User = Depends(require_permission("atm:maintenance")),
    db: AsyncSession = Depends(get_db)
):
    """Sets ATM to ONLINE, MAINTENANCE, or DISABLED with audited justification."""
    stmt = select(Atm).options(selectinload(Atm.sensors), selectinload(Atm.inventories)).where(Atm.id == atm_id)
    res = await db.execute(stmt)
    atm = res.scalar_one_or_none()
    if not atm:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ATM not found.")

    if atm.status == AtmStatus.LOCKDOWN and current_user.role not in [UserRole.SECURITY_ANALYST, UserRole.SUPER_ADMIN]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only Security Analysts or Super Admins can release an ATM from LOCKDOWN mode."
        )

    old_status = atm.status.value
    atm.status = payload.status

    await write_audit_log(
        db=db,
        action="ATM_STATUS_CHANGED",
        resource_type="ATM",
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        resource_id=atm.atm_code,
        payload={"old_status": old_status, "new_status": payload.status.value, "reason": payload.reason}
    )

    await db.commit()
    await db.refresh(atm)
    return atm


@router.post("/{atm_id}/sensor", response_model=AtmResponse)
async def update_sensor_state(
    atm_id: int,
    payload: SensorUpdateRequest,
    current_user: User = Depends(require_permission("atm:sensors")),
    db: AsyncSession = Depends(get_db)
):
    """
    Updates an individual sensor state.
    If TAMPER sensor is set to ALERT, automatically initiates Emergency Lockdown and incident dispatch!
    """
    stmt = select(Atm).options(selectinload(Atm.sensors), selectinload(Atm.inventories)).where(Atm.id == atm_id)
    res = await db.execute(stmt)
    atm = res.scalar_one_or_none()
    if not atm:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ATM not found.")

    # Find sensor
    sensor = next((s for s in atm.sensors if s.sensor_type == payload.sensor_type), None)
    if not sensor:
        sensor = AtmSensor(atm_id=atm.id, sensor_type=payload.sensor_type, state=payload.state)
        db.add(sensor)
        atm.sensors.append(sensor)
    else:
        sensor.state = payload.state
        sensor.last_updated = datetime.datetime.now(datetime.timezone.utc)

    # Check for Tamper or Alert trigger
    if payload.sensor_type == SensorType.TAMPER and payload.state == SensorState.ALERT and payload.trigger_alert:
        await ThreatDetectionEngine.handle_tamper_event(
            db=db,
            atm=atm,
            sensor_type="TAMPER",
            details={"state": "ALERT", "operator_simulated": True}
        )
    elif payload.state == SensorState.ALERT and payload.trigger_alert:
        # Correlated warning
        atm.security_status = f"WARNING_{payload.sensor_type.value}"

    await write_audit_log(
        db=db,
        action="ATM_SENSOR_UPDATED",
        resource_type="ATM_SENSOR",
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        resource_id=f"{atm.atm_code}:{payload.sensor_type.value}",
        payload={"sensor": payload.sensor_type.value, "new_state": payload.state.value}
    )

    await db.commit()
    await db.refresh(atm)
    return atm


@router.post("/{atm_id}/unlock", response_model=AtmResponse)
async def release_lockdown(
    atm_id: int,
    reason: str = Query(..., min_length=10, description="Mandatory security justification"),
    current_user: User = Depends(require_permission("atm:lockdown")),
    db: AsyncSession = Depends(get_db)
):
    """
    Releases an ATM from LOCKDOWN mode.
    Requires SECURITY_ANALYST or SUPER_ADMIN role with mandatory documented justification.
    """
    stmt = select(Atm).options(selectinload(Atm.sensors), selectinload(Atm.inventories)).where(Atm.id == atm_id)
    res = await db.execute(stmt)
    atm = res.scalar_one_or_none()
    if not atm:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ATM not found.")

    atm.status = AtmStatus.ONLINE
    atm.security_status = "SECURE"

    # Reset tamper sensor to NORMAL
    for s in atm.sensors:
        if s.sensor_type == SensorType.TAMPER:
            s.state = SensorState.NORMAL

    await write_audit_log(
        db=db,
        action="ATM_LOCKDOWN_RELEASED",
        resource_type="ATM",
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        resource_id=atm.atm_code,
        payload={"reason": reason, "released_by": current_user.username}
    )

    await db.commit()
    await db.refresh(atm)
    return atm
