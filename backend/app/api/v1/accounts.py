import datetime
from decimal import Decimal
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.db.session import get_db
from app.db.models.models import (
    Account, Card, Transaction, TransactionType, TransactionStatus, 
    User, Customer, Atm, CardStatus
)
from app.schemas.account import (
    BalanceInquiryResponse, MiniStatementResponse, MiniStatementItem
)
from app.schemas.auth import ChangePinRequest
from app.core.deps import get_current_user, verify_account_ownership
from app.core.security import verify_pin, hash_pin
from app.services.pin_policy import PinPolicyService
from app.services.otp import OtpService
from app.audit.writer import write_audit_log

router = APIRouter(prefix="/accounts", tags=["Customer Accounts"])


@router.get("/me/balance", response_model=BalanceInquiryResponse)
async def balance_inquiry(
    atm_id: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Returns current and available account balance, along with remaining daily withdrawal quota."""
    # Find customer account
    stmt = (
        select(Account, Customer)
        .join(Customer, Account.customer_id == Customer.id)
        .where(Customer.user_id == current_user.id)
    )
    res = await db.execute(stmt)
    row = res.first()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer account record not found.")
    account, customer = row

    # Calculate today's withdrawals against daily limit
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    start_of_day = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)

    stmt_today = select(func.sum(Transaction.amount)).where(
        Transaction.account_id == account.id,
        Transaction.type == TransactionType.WITHDRAWAL,
        Transaction.status == TransactionStatus.APPROVED,
        Transaction.created_at >= start_of_day
    )
    res_today = await db.execute(stmt_today)
    withdrawn_today = res_today.scalar() or Decimal("0.00")
    daily_remaining = max(Decimal("0.00"), account.daily_withdrawal_limit - withdrawn_today)

    atm_code = "WEB-PORTAL"
    if atm_id:
        stmt_atm = select(Atm.atm_code).where(Atm.id == atm_id)
        res_atm = await db.execute(stmt_atm)
        code = res_atm.scalar()
        if code:
            atm_code = code

    # Audit balance check
    await write_audit_log(
        db=db,
        action="BALANCE_INQUIRY",
        resource_type="ACCOUNT",
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        resource_id=account.account_number,
        payload={"atm_code": atm_code, "balance": str(account.balance)}
    )
    await db.commit()

    return BalanceInquiryResponse(
        account_number=account.account_number,
        balance=account.balance,
        currency=account.currency,
        available_balance=account.balance,
        daily_limit_remaining=daily_remaining,
        atm_code=atm_code
    )


@router.get("/me/mini-statement", response_model=MiniStatementResponse)
async def mini_statement(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Returns the last 10 transactions executed on the customer's account."""
    stmt_acc = select(Account).join(Customer).where(Customer.user_id == current_user.id)
    res_acc = await db.execute(stmt_acc)
    account = res_acc.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found.")

    stmt_tx = (
        select(Transaction)
        .where(Transaction.account_id == account.id)
        .order_by(Transaction.created_at.desc())
        .limit(10)
    )
    res_tx = await db.execute(stmt_tx)
    txns = res_tx.scalars().all()

    items = []
    for t in txns:
        desc = f"{t.type.value} at ATM #{t.atm_id}"
        if t.type == TransactionType.TRANSFER:
            desc = f"Transfer to Acc #{t.related_account_id or 'EXT'}"
        items.append(MiniStatementItem(
            id=t.id,
            type=t.type.value,
            amount=t.amount,
            status=t.status.value,
            created_at=t.created_at,
            receipt_no=t.receipt_no,
            description=desc
        ))

    await write_audit_log(
        db=db,
        action="MINI_STATEMENT_VIEWED",
        resource_type="ACCOUNT",
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        resource_id=account.account_number,
        payload={"count": len(items)}
    )
    await db.commit()

    return MiniStatementResponse(
        account_number=account.account_number,
        current_balance=account.balance,
        currency=account.currency,
        transactions=items
    )


@router.post("/me/change-pin")
async def change_pin(
    payload: ChangePinRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Changes customer ATM card PIN:
    - Validates current PIN with Argon2id
    - Enforces strict PIN security policy (no weak PINs, sequences, identical digits, years)
    - Verifies confirm PIN match
    - Updates pin_hash with new Argon2id hash and resets pin_failed_attempts
    """
    if payload.new_pin != payload.confirm_pin:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New PIN and confirmation PIN do not match.")

    # 1. Enforce PIN Policy
    valid, errors = PinPolicyService.validate_pin(payload.new_pin)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"PIN policy violation: {'; '.join(errors)}"
        )

    # 2. Lookup Card
    stmt = (
        select(Card)
        .join(Account, Card.account_id == Account.id)
        .join(Customer, Account.customer_id == Customer.id)
        .where(Customer.user_id == current_user.id)
    )
    res = await db.execute(stmt)
    card = res.scalar_one_or_none()
    if not card:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Payment card not found.")

    if card.status != CardStatus.ACTIVE:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot change PIN on non-active card.")

    # 3. Verify current PIN
    if not verify_pin(payload.current_pin, card.pin_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current PIN is incorrect.")

    # 4. Hash and save new PIN
    card.pin_hash = hash_pin(payload.new_pin)
    card.pin_failed_attempts = 0
    card.pin_changed_at = datetime.datetime.now(datetime.timezone.utc)

    await write_audit_log(
        db=db,
        action="PIN_CHANGED",
        resource_type="CARD",
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        resource_id=f"CARD-••••-{card.last4}",
        payload={"card_last4": card.last4}
    )

    await db.commit()
    return {"status": "SUCCESS", "message": "ATM PIN updated successfully."}
