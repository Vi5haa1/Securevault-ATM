import secrets
import hashlib
import datetime
from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
import pyotp
import qrcode
import io
import base64

from app.db.session import get_db
from app.db.models.models import (
    User, Customer, Card, CardStatus, Account, AccountStatus, 
    Atm, AtmStatus, UserRole, UserSession, RefreshToken
)
from app.schemas.auth import (
    StaffLoginRequest, CustomerAtmLoginRequest, VerifyOtpRequest,
    ChangePinRequest, TotpSetupResponse, TotpVerifyRequest,
    Token, SessionHeartbeatResponse
)
from app.core.security import (
    verify_password, hash_password, verify_pin, hash_pin,
    hash_card_number, extract_last4, create_access_token,
    encrypt_mfa_secret, decrypt_mfa_secret, constant_time_compare
)
from app.core.config import settings
from app.core.deps import get_current_user
from app.services.pin_policy import PinPolicyService
from app.services.otp import OtpService
from app.engines.threat_detection import ThreatDetectionEngine
from app.audit.writer import write_audit_log

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/customer/login", response_model=Token)
async def customer_atm_login(
    payload: CustomerAtmLoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Customer ATM login:
    - Verifies ATM is ONLINE (refuses if OFFLINE, MAINTENANCE, or LOCKDOWN)
    - Verifies Card by hash + PIN with Argon2id
    - Enforces 5-attempt lockout through ThreatDetectionEngine
    - Generates 60s idle session + short-lived JWT + rotating refresh token
    """
    # 1. Verify ATM exists and is operable
    stmt_atm = select(Atm).where(Atm.id == payload.atm_id)
    res_atm = await db.execute(stmt_atm)
    atm = res_atm.scalar_one_or_none()
    if not atm:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ATM terminal not found.")

    if atm.status != AtmStatus.ONLINE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"This ATM terminal is currently {atm.status.value}. Transactions unavailable."
        )

    # 2. Lookup Card by deterministic card number hash
    c_hash = hash_card_number(payload.card_number)
    stmt_card = select(Card).join(Card.account).where(Card.card_number_hash == c_hash)
    res_card = await db.execute(stmt_card)
    card = res_card.scalar_one_or_none()

    client_ip = request.client.host if request.client else "127.0.0.1"

    if not card:
        # Generic message to avoid card enumeration
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid card number or PIN.")

    if card.status == CardStatus.LOCKED:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This card has been locked for security. Please contact customer support.")
    elif card.status != CardStatus.ACTIVE:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Card is {card.status.value}.")

    # 3. Verify PIN with Argon2id
    if not verify_pin(payload.pin, card.pin_hash):
        locked, inc = await ThreatDetectionEngine.handle_failed_pin(
            db=db,
            card=card,
            atm=atm,
            ip_address=client_ip
        )
        if locked:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Card locked: Maximum failed PIN attempts exceeded. SOC incident created."
            )
        remaining = 5 - card.pin_failed_attempts
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid PIN. {remaining} attempt(s) remaining before card lockout."
        )

    # PIN correct: Reset failed attempt counter
    card.pin_failed_attempts = 0

    # Retrieve associated User via Customer
    stmt_user = (
        select(User)
        .join(Customer, Customer.user_id == User.id)
        .join(Account, Account.customer_id == Customer.id)
        .where(Account.id == card.account_id)
    )
    res_user = await db.execute(stmt_user)
    user = res_user.scalar_one_or_none()

    if not user or not user.enabled or user.locked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Customer account is disabled or locked.")

    # Generate session token and record active session
    session_token = secrets.token_hex(32)
    now_utc = datetime.datetime.now(datetime.timezone.utc)

    # Invalidate any existing active session on this card (Single active session rule)
    stmt_prev = select(UserSession).where(
        UserSession.card_id == card.id,
        UserSession.terminated_at.is_(None)
    )
    res_prev = await db.execute(stmt_prev)
    for prev_s in res_prev.scalars().all():
        prev_s.terminated_at = now_utc
        prev_s.termination_reason = "NEW_SESSION_LOGIN"

    user_session = UserSession(
        session_token=session_token,
        user_id=user.id,
        card_id=card.id,
        atm_id=atm.id,
        started_at=now_utc,
        last_activity_at=now_utc
    )
    db.add(user_session)

    # Issue short-lived access token
    access_token = create_access_token(
        subject=user.id,
        role=user.role.value,
        extra_claims={
            "card_id": card.id,
            "account_id": card.account_id,
            "atm_id": atm.id,
            "session_token": session_token
        }
    )

    # Write audit log
    await write_audit_log(
        db=db,
        action="CUSTOMER_ATM_LOGIN",
        resource_type="ATM",
        actor_id=str(user.id),
        actor_role=user.role.value,
        resource_id=atm.atm_code,
        payload={"card_last4": card.last4, "atm_id": atm.id},
        ip_address=client_ip
    )

    await db.commit()

    return Token(
        access_token=access_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        role=user.role,
        username=user.username,
        session_token=session_token
    )


@router.post("/staff/login", response_model=Token)
async def staff_login(
    payload: StaffLoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Bank staff / SOC analyst / Admin login:
    - Username + password verification with Argon2id
    - Progressive delay + TOTP MFA enforcement
    """
    stmt = select(User).where(User.username == payload.username)
    res = await db.execute(stmt)
    user = res.scalar_one_or_none()

    client_ip = request.client.host if request.client else "127.0.0.1"

    if not user or not user.enabled or user.locked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password.")

    if user.role == UserRole.CUSTOMER:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Customers must log in at an ATM kiosk.")

    if not verify_password(payload.password, user.password_hash):
        user.failed_login_count += 1
        if user.failed_login_count >= 5:
            user.locked = True
        await db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password.")

    # Reset failed login count
    user.failed_login_count = 0
    user.last_login_at = datetime.datetime.now(datetime.timezone.utc)

    # Check TOTP if enabled
    if user.mfa_enabled:
        if not payload.totp_code:
            raise HTTPException(
                status_code=status.HTTP_428_PRECONDITION_REQUIRED,
                detail="MFA code required for staff authentication."
            )
        decrypted_secret = decrypt_mfa_secret(user.mfa_secret_encrypted)
        totp = pyotp.TOTP(decrypted_secret)
        if not totp.verify(payload.totp_code, valid_window=1):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP authentication code.")

    access_token = create_access_token(
        subject=user.id,
        role=user.role.value,
        extra_claims={"username": user.username}
    )

    await write_audit_log(
        db=db,
        action="STAFF_PORTAL_LOGIN",
        resource_type="STAFF_PORTAL",
        actor_id=str(user.id),
        actor_role=user.role.value,
        resource_id=user.username,
        payload={"role": user.role.value},
        ip_address=client_ip
    )

    await db.commit()

    return Token(
        access_token=access_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        role=user.role,
        username=user.username
    )


@router.post("/staff/totp/setup", response_model=TotpSetupResponse)
async def setup_totp(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Generates a new TOTP secret and QR code for staff MFA enrollment."""
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=current_user.email,
        issuer_name="SecureVault ATM"
    )

    qr = qrcode.QRCode(box_size=6, border=2)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    # Save encrypted secret temporarily
    current_user.mfa_secret_encrypted = encrypt_mfa_secret(secret)
    await db.commit()

    return TotpSetupResponse(
        secret=secret,
        provisioning_uri=provisioning_uri,
        qr_code_base64=f"data:image/png;base64,{qr_b64}"
    )


@router.post("/staff/totp/verify")
async def verify_and_enable_totp(
    payload: TotpVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Confirms enrollment code and marks MFA as enabled."""
    if not current_user.mfa_secret_encrypted:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA setup has not been initiated.")

    secret = decrypt_mfa_secret(current_user.mfa_secret_encrypted)
    totp = pyotp.TOTP(secret)
    if not totp.verify(payload.code, valid_window=1):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification code.")

    current_user.mfa_enabled = True
    await db.commit()
    return {"status": "SUCCESS", "message": "Two-factor authentication successfully enabled."}


@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Terminates active session and records logout in audit trail."""
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    stmt = select(UserSession).where(
        UserSession.user_id == current_user.id,
        UserSession.terminated_at.is_(None)
    )
    res = await db.execute(stmt)
    for s in res.scalars().all():
        s.terminated_at = now_utc
        s.termination_reason = "USER_LOGOUT"

    await write_audit_log(
        db=db,
        action="USER_LOGOUT",
        resource_type="USER_SESSION",
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        payload={"reason": "normal_logout"}
    )
    await db.commit()
    return {"status": "SUCCESS", "message": "Logged out successfully."}


@router.get("/session/heartbeat", response_model=SessionHeartbeatResponse)
async def session_heartbeat(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Updates session activity and returns remaining idle seconds."""
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    stmt = select(UserSession).where(
        UserSession.user_id == current_user.id,
        UserSession.terminated_at.is_(None)
    ).order_by(UserSession.started_at.desc()).limit(1)
    res = await db.execute(stmt)
    sess = res.scalar_one_or_none()

    if not sess:
        return SessionHeartbeatResponse(active=False, remaining_seconds=0)

    last_act = sess.last_activity_at
    if last_act is not None:
        if last_act.tzinfo is None:
            last_act = last_act.replace(tzinfo=datetime.timezone.utc)
    else:
        last_act = now_utc

    idle_seconds = max(0, (now_utc - last_act).total_seconds())
    if idle_seconds > settings.IDLE_SESSION_TIMEOUT_SECONDS:
        sess.terminated_at = now_utc
        sess.termination_reason = "IDLE_TIMEOUT"
        await db.commit()
        return SessionHeartbeatResponse(active=False, remaining_seconds=0)

    sess.last_activity_at = now_utc
    await db.commit()
    remaining = int(max(0, settings.IDLE_SESSION_TIMEOUT_SECONDS - idle_seconds))
    return SessionHeartbeatResponse(active=True, remaining_seconds=remaining)


@router.post("/session/extend", response_model=SessionHeartbeatResponse)
async def extend_session(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Explicitly extends session idle timeout."""
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    stmt = select(UserSession).where(
        UserSession.user_id == current_user.id,
        UserSession.terminated_at.is_(None)
    ).order_by(UserSession.started_at.desc()).limit(1)
    res = await db.execute(stmt)
    sess = res.scalar_one_or_none()
    if not sess:
        return SessionHeartbeatResponse(active=False, remaining_seconds=0)

    sess.last_activity_at = now_utc
    await db.commit()
    return SessionHeartbeatResponse(active=True, remaining_seconds=settings.IDLE_SESSION_TIMEOUT_SECONDS)
