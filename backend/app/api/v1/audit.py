from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.db.session import get_db
from app.db.models.models import AuditLog, User
from app.schemas.audit import AuditLogResponse, AuditVerifyResponse, TamperDemoRequest
from app.core.deps import require_permission, get_current_user_optional
from app.audit.verifier import verify_audit_chain
from app.audit.hash_chain import compute_audit_hash

router = APIRouter(prefix="/audit", tags=["Cryptographic Audit Trail"])


@router.get("/logs", response_model=List[AuditLogResponse])
async def list_audit_logs(
    limit: int = Query(50, le=500),
    current_user: User = Depends(require_permission("soc:audit_verify")),
    db: AsyncSession = Depends(get_db)
):
    """Retrieves immutable append-only audit trail records."""
    stmt = select(AuditLog).order_by(AuditLog.sequence_no.desc()).limit(limit)
    res = await db.execute(stmt)
    return res.scalars().all()


@router.get("/verify", response_model=AuditVerifyResponse)
async def verify_audit_trail(
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: AsyncSession = Depends(get_db)
):
    """
    Cryptographically verifies the entire SHA-256 audit chain.
    Walks from genesis block, recalculates all hashes and prev_hash links,
    and returns exact status and broken index if tampered.
    """
    result = await verify_audit_chain(db)
    return AuditVerifyResponse(**result)


@router.post("/tamper-demo")
async def simulate_tamper_demo(
    payload: TamperDemoRequest,
    current_user: User = Depends(require_permission("soc:tamper_demo")),
    db: AsyncSession = Depends(get_db)
):
    """
    DEVELOPER & DEMO FEATURE:
    Deliberately modifies a single audit log row payload/action in the database
    to demonstrably prove that the cryptographic hash chain catches unauthorized tampering!
    """
    stmt = select(AuditLog).where(AuditLog.id == payload.log_id)
    res = await db.execute(stmt)
    log_entry = res.scalar_one_or_none()
    if not log_entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit log entry not found.")

    # Tamper with the action text without updating the SHA-256 hash
    log_entry.action = payload.modified_action
    await db.commit()

    return {
        "status": "TAMPER_INJECTED",
        "message": f"Audit record #{log_entry.sequence_no} (ID {log_entry.id}) action modified to '{payload.modified_action}'. Verify endpoint will now report BROKEN.",
        "sequence_no": log_entry.sequence_no,
        "log_id": log_entry.id
    }


@router.post("/restore-demo")
async def restore_tamper_demo(
    log_id: int = Query(...),
    current_user: User = Depends(require_permission("soc:tamper_demo")),
    db: AsyncSession = Depends(get_db)
):
    """
    Restores the valid hash on a tampered record so verification returns to VALID.
    """
    stmt = select(AuditLog).where(AuditLog.id == log_id)
    res = await db.execute(stmt)
    log_entry = res.scalar_one_or_none()
    if not log_entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit log entry not found.")

    # Recompute valid hash
    timestamp_str = log_entry.created_at.strftime("%Y-%m-%dT%H:%M:%S")
    log_entry.hash = compute_audit_hash(
        prev_hash=log_entry.prev_hash,
        sequence_no=log_entry.sequence_no,
        actor_id=log_entry.actor_id,
        action=log_entry.action,
        resource_type=log_entry.resource_type,
        resource_id=log_entry.resource_id,
        payload=log_entry.payload,
        timestamp_str=timestamp_str,
    )
    await db.commit()
    return {"status": "RESTORED", "message": f"Audit record #{log_entry.sequence_no} hash recomputed. Chain intact."}
