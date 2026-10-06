import datetime
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.db.session import get_db
from app.db.models.models import Certificate, Atm, User
from app.core.deps import require_permission, get_current_user
from app.services.crypto_vault import PkiService
from app.audit.writer import write_audit_log

router = APIRouter(prefix="/security/certificates", tags=["PKI & Digital Certificates"])


class CertificateRevokeRequest(BaseModel):
    reason: str = Field(..., example="Compromised ATM private key suspected")


class CertificateIssueRequest(BaseModel):
    atm_code: str
    atm_id: Optional[int] = None


@router.get("/")
async def list_certificates(
    current_user: User = Depends(require_permission("soc:dashboard")),
    db: AsyncSession = Depends(get_db)
):
    """Lists all synthetic X.509 client certificates for ATMs with expiration flags."""
    stmt = select(Certificate).order_by(Certificate.created_at.desc())
    res = await db.execute(stmt)
    certs = res.scalars().all()

    now = datetime.datetime.now(datetime.timezone.utc)
    results = []
    for c in certs:
        # Check if expiring within 30 days
        is_expiring = False
        if c.status == "VALID" and c.valid_until:
            days_left = (c.valid_until - now).days
            if 0 < days_left <= 30:
                is_expiring = True
            elif days_left <= 0:
                c.status = "EXPIRED"

        results.append({
            "id": c.id,
            "cert_id": c.cert_id,
            "subject": c.subject,
            "issuer": c.issuer,
            "serial_number": c.serial_number,
            "fingerprint": c.fingerprint,
            "valid_from": c.valid_from.isoformat() if c.valid_from else None,
            "valid_until": c.valid_until.isoformat() if c.valid_until else None,
            "status": "EXPIRING" if is_expiring else c.status,
            "revocation_reason": c.revocation_reason,
            "public_key_pem": c.public_key_pem,
            "atm_id": c.atm_id,
            "created_at": c.created_at.isoformat() if c.created_at else None
        })

    return results


@router.post("/issue")
async def issue_certificate(
    payload: CertificateIssueRequest,
    current_user: User = Depends(require_permission("admin:users")),
    db: AsyncSession = Depends(get_db)
):
    """Issues a new X.509 client certificate for an ATM terminal (RBAC: Bank Admin)."""
    cert = await PkiService.issue_atm_certificate(
        db=db,
        atm_code=payload.atm_code,
        atm_id=payload.atm_id
    )
    await write_audit_log(
        db=db,
        action="CERTIFICATE_ISSUED",
        resource_type="PKI_CERTIFICATE",
        resource_id=cert.cert_id,
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        payload={"atm_code": payload.atm_code, "cert_id": cert.cert_id}
    )
    await db.commit()
    return {"status": "SUCCESS", "cert_id": cert.cert_id, "fingerprint": cert.fingerprint}


@router.post("/{cert_id}/revoke")
async def revoke_certificate(
    cert_id: str,
    payload: CertificateRevokeRequest,
    current_user: User = Depends(require_permission("admin:users")),
    db: AsyncSession = Depends(get_db)
):
    """Revokes an X.509 certificate and blocks ATM mTLS connectivity."""
    try:
        cert = await PkiService.revoke_certificate(
            db=db,
            cert_id=cert_id,
            reason=payload.reason,
            actor=str(current_user.id)
        )
        return {"status": "REVOKED", "cert_id": cert.cert_id, "reason": cert.revocation_reason}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
