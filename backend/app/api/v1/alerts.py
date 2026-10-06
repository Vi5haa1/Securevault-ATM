from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.db.session import get_db
from app.db.models.models import Alert, AlertStatus, SeverityLevel, User
from app.schemas.incident import AlertResponse
from app.core.deps import require_permission
from app.audit.writer import write_audit_log

router = APIRouter(prefix="/alerts", tags=["Alerts Management"])


@router.get("", response_model=List[AlertResponse])
async def list_alerts(
    status_filter: Optional[AlertStatus] = None,
    severity: Optional[SeverityLevel] = None,
    limit: int = Query(50, le=200),
    current_user: User = Depends(require_permission("soc:alerts")),
    db: AsyncSession = Depends(get_db)
):
    """Lists security alerts with optional status and severity filtering."""
    stmt = select(Alert).order_by(Alert.created_at.desc()).limit(limit)
    if status_filter:
        stmt = stmt.where(Alert.status == status_filter)
    if severity:
        stmt = stmt.where(Alert.severity == severity)

    res = await db.execute(stmt)
    return res.scalars().all()


@router.post("/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(
    alert_id: int,
    current_user: User = Depends(require_permission("soc:alerts")),
    db: AsyncSession = Depends(get_db)
):
    """Marks an alert as ACKNOWLEDGED by the on-duty analyst."""
    stmt = select(Alert).where(Alert.id == alert_id)
    res = await db.execute(stmt)
    alert = res.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found.")

    alert.status = AlertStatus.ACKNOWLEDGED
    await write_audit_log(
        db=db,
        action="ALERT_ACKNOWLEDGED",
        resource_type="ALERT",
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        resource_id=str(alert.id),
        payload={"alert_title": alert.title}
    )
    await db.commit()
    await db.refresh(alert)
    return alert


@router.post("/{alert_id}/close", response_model=AlertResponse)
async def close_alert(
    alert_id: int,
    current_user: User = Depends(require_permission("soc:alerts")),
    db: AsyncSession = Depends(get_db)
):
    """Marks an alert as CLOSED."""
    stmt = select(Alert).where(Alert.id == alert_id)
    res = await db.execute(stmt)
    alert = res.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found.")

    alert.status = AlertStatus.CLOSED
    await write_audit_log(
        db=db,
        action="ALERT_CLOSED",
        resource_type="ALERT",
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        resource_id=str(alert.id),
        payload={"alert_title": alert.title}
    )
    await db.commit()
    await db.refresh(alert)
    return alert
