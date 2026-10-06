import datetime
from decimal import Decimal
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.db.models.models import (
    User, Customer, Account, Card, Atm, BehaviorProfile, 
    SecurityPolicy, UserRole, AccountStatus, CardStatus
)
from app.core.deps import require_permission, get_current_user_optional, get_current_user
from app.core.security import hash_password, hash_pin, hash_card_number
from app.audit.writer import write_audit_log

router = APIRouter(prefix="/admin", tags=["Bank Administration"])


class PolicyUpdateRequest(BaseModel):
    value: Dict[str, Any]
    description: Optional[str] = None


class CustomerCreateRequest(BaseModel):
    username: str
    email: str
    phone: str
    full_name: str
    home_city: str
    initial_balance: Decimal = Decimal("25000.00")
    pin: str = "4826"


class StaffCreateRequest(BaseModel):
    username: str
    email: str
    phone: str
    password: str
    role: UserRole


@router.get("/policies")
async def get_security_policies(
    current_user: User = Depends(require_permission("admin:policies")),
    db: AsyncSession = Depends(get_db)
):
    """Retrieves all active dynamic security policies and thresholds."""
    stmt = select(SecurityPolicy)
    res = await db.execute(stmt)
    return res.scalars().all()


@router.put("/policies/{key}")
async def update_security_policy(
    key: str,
    payload: PolicyUpdateRequest,
    current_user: User = Depends(require_permission("admin:policies")),
    db: AsyncSession = Depends(get_db)
):
    """Updates a dynamic security policy and logs a cryptographic before/after diff."""
    stmt = select(SecurityPolicy).where(SecurityPolicy.key == key)
    res = await db.execute(stmt)
    policy = res.scalar_one_or_none()

    if not policy:
        policy = SecurityPolicy(
            key=key,
            value=payload.value,
            description=payload.description or f"Policy {key}",
            updated_by=current_user.id
        )
        db.add(policy)
        old_val = {}
    else:
        old_val = policy.value
        policy.value = payload.value
        if payload.description:
            policy.description = payload.description
        policy.updated_by = current_user.id
        policy.updated_at = datetime.datetime.now(datetime.timezone.utc)

    await write_audit_log(
        db=db,
        action="SECURITY_POLICY_CHANGED",
        resource_type="SECURITY_POLICY",
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        resource_id=key,
        payload={"policy_key": key, "old_value": old_val, "new_value": payload.value}
    )

    await db.commit()
    await db.refresh(policy)
    return policy


@router.get("/customers")
async def list_customers(
    limit: int = Query(50, le=200),
    current_user: User = Depends(require_permission("admin:customers")),
    db: AsyncSession = Depends(get_db)
):
    """Lists customers with their accounts, cards, and profile summary."""
    stmt = (
        select(Customer)
        .options(
            selectinload(Customer.user),
            selectinload(Customer.accounts).selectinload(Account.cards),
            selectinload(Customer.behavior_profile)
        )
        .limit(limit)
    )
    res = await db.execute(stmt)
    customers = res.scalars().all()

    output = []
    for c in customers:
        acc_info = []
        for a in c.accounts:
            card_info = [{"id": card.id, "last4": card.last4, "status": card.status.value} for card in a.cards]
            acc_info.append({
                "id": a.id,
                "account_number": a.account_number,
                "balance": float(a.balance),
                "status": a.status.value,
                "cards": card_info
            })
        output.append({
            "id": c.id,
            "username": c.user.username if c.user else "",
            "full_name": c.full_name,
            "home_city": c.home_city,
            "enabled": c.user.enabled if c.user else False,
            "locked": c.user.locked if c.user else False,
            "accounts": acc_info,
            "profile": {
                "avg_withdrawal": float(c.behavior_profile.avg_withdrawal) if c.behavior_profile else 0,
                "typical_cities": c.behavior_profile.typical_cities if c.behavior_profile else [c.home_city]
            } if c.behavior_profile else None
        })
    return output


@router.post("/customers/{customer_id}/toggle-lock")
async def toggle_customer_lock(
    customer_id: int,
    current_user: User = Depends(require_permission("admin:customers")),
    db: AsyncSession = Depends(get_db)
):
    """Toggles locked status on a customer user and cards."""
    stmt = select(Customer).options(selectinload(Customer.user), selectinload(Customer.accounts).selectinload(Account.cards)).where(Customer.id == customer_id)
    res = await db.execute(stmt)
    cust = res.scalar_one_or_none()
    if not cust or not cust.user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found.")

    new_state = not cust.user.locked
    cust.user.locked = new_state
    if not new_state:
        cust.user.failed_login_count = 0

    # Also sync card lock
    for a in cust.accounts:
        for c in a.cards:
            c.status = CardStatus.LOCKED if new_state else CardStatus.ACTIVE
            if not new_state:
                c.pin_failed_attempts = 0

    await write_audit_log(
        db=db,
        action="CUSTOMER_LOCK_TOGGLED",
        resource_type="CUSTOMER",
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        resource_id=str(cust.id),
        payload={"new_locked_state": new_state, "username": cust.user.username}
    )

    await db.commit()
    return {"status": "SUCCESS", "locked": new_state}


@router.get("/staff")
async def list_staff_users(
    current_user: User = Depends(require_permission("admin:staff")),
    db: AsyncSession = Depends(get_db)
):
    """Lists internal bank operators, analysts, and administrators."""
    stmt = select(User).where(User.role != UserRole.CUSTOMER)
    res = await db.execute(stmt)
    users = res.scalars().all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "role": u.role.value,
            "enabled": u.enabled,
            "locked": u.locked,
            "mfa_enabled": u.mfa_enabled,
            "last_login_at": u.last_login_at
        } for u in users
    ]


@router.post("/staff")
async def create_staff_user(
    payload: StaffCreateRequest,
    current_user: User = Depends(require_permission("admin:staff")),
    db: AsyncSession = Depends(get_db)
):
    """Creates a new staff operator or security analyst."""
    new_user = User(
        username=payload.username,
        email=payload.email,
        phone=payload.phone,
        password_hash=hash_password(payload.password),
        role=payload.role,
        enabled=True,
        mfa_enabled=False
    )
    db.add(new_user)
    await db.flush()

    await write_audit_log(
        db=db,
        action="STAFF_USER_CREATED",
        resource_type="USER",
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        resource_id=new_user.username,
        payload={"role": payload.role.value}
    )
    await db.commit()
    return {"status": "SUCCESS", "user_id": new_user.id, "username": new_user.username}


@router.get("/mongodb/status")
async def get_mongodb_status(
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Returns local MongoDB Compass connection status and collections."""
    from app.db.mongodb import check_mongo_connection
    return await check_mongo_connection()


@router.post("/mongodb/sync")
async def trigger_mongodb_sync(
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Triggers complete sync of SQLite data to local MongoDB Compass database 'securevault_db'."""
    from app.db.mongo_sync import sync_all_to_mongodb
    return sync_all_to_mongodb()
