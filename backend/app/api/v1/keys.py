import datetime
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.db.session import get_db
from app.db.models.models import HsmKey, KeyUsageAudit, User
from app.core.deps import require_permission
from app.services.crypto_vault import HsmKeyVault
from app.audit.writer import write_audit_log

router = APIRouter(prefix="/security/keys", tags=["HSM Simulator & Key Management"])


class KeyGenerateRequest(BaseModel):
    purpose: str = Field(..., example="TRANSACTION_ENCRYPTION")
    algorithm: str = Field(default="AES-256-GCM")


@router.get("/")
async def get_hsm_status_and_keys(
    current_user: User = Depends(require_permission("soc:dashboard")),
    db: AsyncSession = Depends(get_db)
):
    """
    Returns HSM operational telemetry, key slots, and active cryptographic keys.
    Labeled: HSM SIMULATION / DEVELOPMENT ENVIRONMENT.
    Never exposes raw private key material.
    """
    stmt = select(HsmKey).order_by(HsmKey.created_at.desc())
    res = await db.execute(stmt)
    keys = res.scalars().all()

    now = datetime.datetime.now(datetime.timezone.utc)
    active_count = sum(1 for k in keys if k.status == "ACTIVE")
    rotating_count = sum(1 for k in keys if k.status == "ROTATING")
    expired_count = sum(1 for k in keys if k.status == "EXPIRED")

    # Fetch recent usage audits
    stmt_usage = select(KeyUsageAudit).order_by(KeyUsageAudit.timestamp.desc()).limit(20)
    res_usage = await db.execute(stmt_usage)
    usages = res_usage.scalars().all()

    formatted_keys = []
    for k in keys:
        days_to_expire = (k.expires_at - now).days if k.expires_at else 90
        formatted_keys.append({
            "id": k.id,
            "key_id": k.key_id,
            "purpose": k.purpose,
            "algorithm": k.algorithm,
            "version": k.version,
            "status": k.status,
            "created_at": k.created_at.isoformat() if k.created_at else None,
            "expires_at": k.expires_at.isoformat() if k.expires_at else None,
            "rotation_due_days": max(0, days_to_expire),
            "usage_count": k.usage_count,
            "is_encrypted_at_rest": True
        })

    return {
        "hsm_status": {
            "environment": "HSM SIMULATION / DEVELOPMENT ENVIRONMENT",
            "hardware_state": "NOMINAL",
            "tamper_state": "SECURE",
            "total_slots": 16,
            "used_slots": len(keys),
            "active_keys": active_count,
            "rotating_keys": rotating_count,
            "expired_keys": expired_count,
            "master_key_derivation": "PBKDF2-HMAC-SHA256 / AES-256-GCM"
        },
        "keys": formatted_keys,
        "recent_usage_audits": [
            {
                "id": u.id,
                "key_id": u.key_id,
                "action": u.action,
                "actor": u.actor,
                "resource": u.resource,
                "timestamp": u.timestamp.isoformat(),
                "success": u.success
            }
            for u in usages
        ]
    }


@router.post("/generate")
async def generate_key(
    payload: KeyGenerateRequest,
    current_user: User = Depends(require_permission("admin:users")),
    db: AsyncSession = Depends(get_db)
):
    """Generates a new cryptographic key in the simulated HSM vault."""
    key = await HsmKeyVault.get_or_create_key(
        db=db,
        purpose=payload.purpose,
        algorithm=payload.algorithm
    )
    await write_audit_log(
        db=db,
        action="HSM_KEY_GENERATED",
        resource_type="HSM_KEY",
        resource_id=key.key_id,
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        payload={"key_id": key.key_id, "purpose": key.purpose, "algorithm": key.algorithm}
    )
    await db.commit()
    return {"status": "SUCCESS", "key_id": key.key_id, "version": key.version}


@router.post("/{key_id}/rotate")
async def rotate_key(
    key_id: str,
    current_user: User = Depends(require_permission("admin:users")),
    db: AsyncSession = Depends(get_db)
):
    """Rotates an existing key to a new version, preserving previous version for decryption."""
    try:
        new_key = await HsmKeyVault.rotate_key(
            db=db,
            key_id=key_id,
            actor=str(current_user.id)
        )
        return {
            "status": "ROTATED",
            "previous_key_id": key_id,
            "new_key_id": new_key.key_id,
            "new_version": new_key.version
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
