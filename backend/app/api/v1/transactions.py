import uuid
import datetime
from decimal import Decimal
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.db.models.models import (
    Transaction, TransactionType, TransactionStatus, RiskLevel,
    Account, AccountStatus, Card, CardStatus, Atm, AtmStatus,
    AtmCashInventory, User, Customer
)
from app.schemas.transaction import (
    WithdrawalRequest, DepositRequest, TransferRequest, 
    TransactionResponse, DenominationBreakdown, ZeroTrustStepTrace
)
from app.core.deps import get_current_user, verify_account_ownership
from app.security.zero_trust_pipeline import ZeroTrustPipeline, ZeroTrustContext
from app.services.denomination import DenominationService, DenominationDispenseError
from app.services.receipt import generate_pdf_receipt
from app.engines.risk_engine import RiskEngine
from app.engines.threat_detection import ThreatDetectionEngine

router = APIRouter(prefix="/transactions", tags=["Banking Transactions"])


def generate_receipt_no() -> str:
    """Generates unique receipt number."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return f"REC-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"


@router.post("/withdraw", response_model=TransactionResponse)
async def withdraw_cash(
    payload: WithdrawalRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Executes cash withdrawal through the unbypassable Zero-Trust Pipeline:
    - Idempotency key deduplication
    - Row-level locking (SELECT ... FOR UPDATE) on Account and Atm inventories
    - Denomination note dispensing algorithm
    - Real-time explainable risk evaluation
    - Append-only cryptographic audit hash chaining
    """
    client_ip = request.client.host if request.client else "127.0.0.1"

    # 1. Idempotency Check: prevent duplicate submissions
    stmt_idemp = select(Transaction).where(Transaction.idempotency_key == payload.idempotency_key)
    res_idemp = await db.execute(stmt_idemp)
    existing_txn = res_idemp.scalar_one_or_none()
    if existing_txn:
        # Return already processed transaction
        return TransactionResponse(
            id=existing_txn.id,
            account_id=existing_txn.account_id,
            atm_id=existing_txn.atm_id,
            type=existing_txn.type,
            amount=existing_txn.amount,
            status=existing_txn.status,
            risk_score=existing_txn.risk_score,
            risk_level=existing_txn.risk_level,
            risk_factors=existing_txn.risk_factors,
            receipt_no=existing_txn.receipt_no,
            created_at=existing_txn.created_at,
            dispensed_notes=[],
            new_balance=None
        )

    # Initialize Zero-Trust Context
    context = ZeroTrustContext(
        db=db,
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        action="ATM_CASH_WITHDRAWAL",
        resource_type="ACCOUNT",
        resource_id=str(payload.account_id),
        ip_address=client_ip,
        device_fingerprint=payload.device_fingerprint,
        payload={"amount": str(payload.amount), "atm_id": payload.atm_id}
    )

    pipeline = ZeroTrustPipeline(context)

    # Step 1: Authenticate
    async def step_auth(ctx: ZeroTrustContext):
        if not current_user.enabled or current_user.locked:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User account is locked or disabled.")
        ctx.add_trace("Authenticate", "PASSED", f"User {current_user.username} authenticated with valid credentials.")

    # Step 2: Authorize & Ownership
    async def step_authz(ctx: ZeroTrustContext):
        stmt_c = select(Customer).where(Customer.user_id == current_user.id)
        res_c = await db.execute(stmt_c)
        customer = res_c.scalar_one_or_none()
        if not customer:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No customer record associated with user.")

        # Check account belongs to customer
        stmt_a = select(Account).where(Account.id == payload.account_id, Account.customer_id == customer.id)
        res_a = await db.execute(stmt_a)
        account = res_a.scalar_one_or_none()
        if not account:
            # Unauthorized access attempt (IDOR)
            await ThreatDetectionEngine.handle_unauthorized_access(
                db=db,
                actor_id=str(current_user.id),
                resource=f"Account:{payload.account_id}",
                attempt_type="IDOR_ACCOUNT_ACCESS",
                ip_address=client_ip
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: Account ownership validation failed.")

        ctx.add_trace("Authorize", "PASSED", f"Ownership of account {account.account_number} verified for customer {customer.full_name}.")

    # Step 3: Validate
    async def step_validate(ctx: ZeroTrustContext):
        if payload.amount <= 0:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Amount must be positive.")
        if payload.amount % 100 != 0:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Withdrawal amount must be a multiple of 100 INR.")

        # Check ATM state
        stmt_atm = select(Atm).where(Atm.id == payload.atm_id)
        res_atm = await db.execute(stmt_atm)
        atm = res_atm.scalar_one_or_none()
        if not atm:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target ATM not found.")
        if atm.status != AtmStatus.ONLINE:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"ATM is currently {atm.status.value}.")

        # Check Account limit
        stmt_acc = select(Account).where(Account.id == payload.account_id)
        res_acc = await db.execute(stmt_acc)
        account = res_acc.scalar_one_or_none()

        if payload.amount > account.per_txn_limit:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Amount exceeds per-transaction limit of INR {account.per_txn_limit:,.2f}.")

        if account.balance < payload.amount:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Insufficient account balance.")

        ctx.add_trace("Validate", "PASSED", f"Amount INR {payload.amount} valid against limits and ATM operational status.")

    # Step 4: Risk Analysis
    async def step_risk(ctx: ZeroTrustContext):
        stmt_atm = select(Atm).where(Atm.id == payload.atm_id)
        res_atm = await db.execute(stmt_atm)
        atm = res_atm.scalar_one_or_none()

        stmt_acc = select(Account).where(Account.id == payload.account_id)
        res_acc = await db.execute(stmt_acc)
        account = res_acc.scalar_one_or_none()

        risk_assessment = await RiskEngine.evaluate_transaction_risk(
            db=db,
            customer_id=account.customer_id,
            atm=atm,
            amount=payload.amount,
            device_fingerprint=payload.device_fingerprint
        )
        ctx.risk_score = risk_assessment.score
        ctx.risk_level = risk_assessment.level.value
        ctx.risk_factors = risk_assessment.to_dict()

        if risk_assessment.level == RiskLevel.CRITICAL:
            ctx.add_trace("RiskAnalysis", "FAILED", f"Critical anomaly score {risk_assessment.score}/100. Automated block triggered.")
        elif risk_assessment.level in [RiskLevel.HIGH, RiskLevel.MEDIUM]:
            ctx.add_trace("RiskAnalysis", "WARNING", f"Elevated risk score {risk_assessment.score}/100 ({risk_assessment.level.value}).")
        else:
            ctx.add_trace("RiskAnalysis", "PASSED", f"Normal baseline score {risk_assessment.score}/100 (LOW).")

    # Step 5: Security Policy
    async def step_policy(ctx: ZeroTrustContext):
        stmt_atm = select(Atm).where(Atm.id == payload.atm_id)
        res_atm = await db.execute(stmt_atm)
        atm = res_atm.scalar_one_or_none()

        # If Critical -> reject and create incident
        if ctx.risk_level == "CRITICAL":
            await ThreatDetectionEngine.handle_suspicious_transaction(
                db=db,
                atm=atm,
                account_id=payload.account_id,
                amount=payload.amount,
                risk_score=ctx.risk_score,
                risk_level=ctx.risk_level,
                risk_factors=ctx.risk_factors
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Security Policy: Transaction blocked due to critical risk score ({ctx.risk_score}/100). SOC incident opened."
            )
        ctx.add_trace("SecurityPolicy", "PASSED", "Transaction permitted under active threat policies.")

    # Step 6: Atomic Execution with Row-Level Locking
    async def step_execute(ctx: ZeroTrustContext) -> Dict[str, Any]:
        # Lock Account row with FOR UPDATE
        stmt_acc = select(Account).where(Account.id == payload.account_id).with_for_update()
        res_acc = await db.execute(stmt_acc)
        account = res_acc.scalar_one()

        if account.balance < payload.amount:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Insufficient account balance (concurrency check).")

        # Lock ATM inventories with FOR UPDATE
        stmt_inv = (
            select(AtmCashInventory)
            .where(AtmCashInventory.atm_id == payload.atm_id)
            .with_for_update()
        )
        res_inv = await db.execute(stmt_inv)
        inventories = res_inv.scalars().all()
        inv_map = {inv.denomination: inv.note_count for inv in inventories}

        # Calculate exact cash note dispensing
        try:
            dispense_plan = DenominationService.calculate_dispense(int(payload.amount), inv_map)
        except DenominationDispenseError as dde:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(dde))

        # Deduct note counts from ATM inventory
        for note in dispense_plan:
            d_val = note["denomination"]
            cnt = note["count"]
            for inv in inventories:
                if inv.denomination == d_val:
                    inv.note_count -= cnt
                    break

        # Deduct ATM total cash
        stmt_atm = select(Atm).where(Atm.id == payload.atm_id).with_for_update()
        res_atm = await db.execute(stmt_atm)
        atm = res_atm.scalar_one()
        atm.cash_total -= payload.amount

        # Check low cash
        if atm.cash_total < atm.low_cash_threshold:
            atm.security_status = "LOW_CASH_WARNING"

        # Deduct Customer Account balance
        account.balance -= payload.amount
        receipt_num = generate_receipt_no()

        # Create Transaction record
        txn = Transaction(
            account_id=account.id,
            atm_id=atm.id,
            type=TransactionType.WITHDRAWAL,
            amount=payload.amount,
            status=TransactionStatus.APPROVED,
            risk_score=ctx.risk_score,
            risk_level=RiskLevel(ctx.risk_level),
            risk_factors=ctx.risk_factors,
            device_fingerprint=payload.device_fingerprint,
            ip_address=ctx.ip_address,
            idempotency_key=payload.idempotency_key,
            receipt_no=receipt_num,
            is_simulated=False
        )
        db.add(txn)
        await db.flush()

        return {
            "transaction": txn,
            "dispensed_notes": [DenominationBreakdown(denomination=d["denomination"], count=d["count"]) for d in dispense_plan],
            "new_balance": account.balance,
            "receipt_no": receipt_num
        }

    pipeline.set_authentication(step_auth)
    pipeline.set_authorization(step_authz)
    pipeline.set_validation(step_validate)
    pipeline.set_risk_analysis(step_risk)
    pipeline.set_security_policy(step_policy)
    pipeline.set_execution(step_execute)

    # Execute pipeline
    await pipeline.run()
    await db.commit()

    exec_res = context.execution_result
    txn: Transaction = exec_res["transaction"]

    return TransactionResponse(
        id=txn.id,
        account_id=txn.account_id,
        atm_id=txn.atm_id,
        type=txn.type,
        amount=txn.amount,
        status=txn.status,
        risk_score=txn.risk_score,
        risk_level=txn.risk_level,
        risk_factors=txn.risk_factors,
        receipt_no=txn.receipt_no,
        dispensed_notes=exec_res["dispensed_notes"],
        new_balance=exec_res["new_balance"],
        created_at=txn.created_at,
        zero_trust_trace=[
            ZeroTrustStepTrace(
                step_name=t.step_name,
                status=t.status,
                details=t.details,
                timestamp=t.timestamp
            ) for t in context.traces
        ]
    )


@router.post("/deposit", response_model=TransactionResponse)
async def deposit_cash(
    payload: DepositRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Simulates cash deposit, replenishing ATM note count and crediting account balance."""
    # Validate account ownership
    account = await verify_account_ownership(payload.account_id, current_user, db)

    # Check ATM
    stmt_atm = select(Atm).where(Atm.id == payload.atm_id)
    res_atm = await db.execute(stmt_atm)
    atm = res_atm.scalar_one_or_none()
    if not atm or atm.status != AtmStatus.ONLINE:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="ATM is not available for deposits.")

    # Calculate total from denomination map
    calculated_total = sum(denom * count for denom, count in payload.denominations.items())
    if Decimal(calculated_total) != payload.amount:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Denomination breakdown total (INR {calculated_total}) does not match declared amount (INR {payload.amount})."
        )

    # Atomic update with row locks
    stmt_a = select(Account).where(Account.id == payload.account_id).with_for_update()
    res_a = await db.execute(stmt_a)
    locked_acc = res_a.scalar_one()
    locked_acc.balance += payload.amount

    # Update ATM inventory
    stmt_inv = select(AtmCashInventory).where(AtmCashInventory.atm_id == payload.atm_id).with_for_update()
    res_inv = await db.execute(stmt_inv)
    inventories = res_inv.scalars().all()

    for denom, count in payload.denominations.items():
        inv = next((i for i in inventories if i.denomination == denom), None)
        if inv:
            inv.note_count += count
        else:
            db.add(AtmCashInventory(atm_id=atm.id, denomination=denom, note_count=count))

    atm.cash_total += payload.amount
    receipt_num = generate_receipt_no()

    txn = Transaction(
        account_id=locked_acc.id,
        atm_id=atm.id,
        type=TransactionType.DEPOSIT,
        amount=payload.amount,
        status=TransactionStatus.APPROVED,
        risk_score=5,
        risk_level=RiskLevel.LOW,
        device_fingerprint=payload.device_fingerprint,
        idempotency_key=payload.idempotency_key,
        receipt_no=receipt_num,
        is_simulated=False
    )
    db.add(txn)
    await db.commit()

    return TransactionResponse(
        id=txn.id,
        account_id=txn.account_id,
        atm_id=txn.atm_id,
        type=txn.type,
        amount=txn.amount,
        status=txn.status,
        risk_score=txn.risk_score,
        risk_level=txn.risk_level,
        receipt_no=txn.receipt_no,
        new_balance=locked_acc.balance,
        created_at=txn.created_at
    )


@router.post("/transfer", response_model=TransactionResponse)
async def transfer_funds(
    payload: TransferRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Executes inter-account fund transfer with payee validation and row locks."""
    # Verify sender ownership
    sender_acc = await verify_account_ownership(payload.source_account_id, current_user, db)

    # Verify receiver exists
    stmt_rcv = select(Account).where(Account.account_number == payload.destination_account_number)
    res_rcv = await db.execute(stmt_rcv)
    receiver_acc = res_rcv.scalar_one_or_none()
    if not receiver_acc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Payee account number not found.")

    if sender_acc.id == receiver_acc.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot transfer funds to the same account.")

    # Row locks ordered by account ID to prevent deadlocks
    first_id, second_id = sorted([sender_acc.id, receiver_acc.id])
    stmt_first = select(Account).where(Account.id == first_id).with_for_update()
    stmt_second = select(Account).where(Account.id == second_id).with_for_update()
    res1 = await db.execute(stmt_first)
    res2 = await db.execute(stmt_second)
    locked_sender = sender_acc if sender_acc.id == first_id else receiver_acc
    locked_receiver = receiver_acc if sender_acc.id == first_id else sender_acc

    if locked_sender.balance < payload.amount:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Insufficient funds for transfer.")

    locked_sender.balance -= payload.amount
    locked_receiver.balance += payload.amount
    receipt_num = generate_receipt_no()

    txn = Transaction(
        account_id=locked_sender.id,
        atm_id=payload.atm_id,
        type=TransactionType.TRANSFER,
        amount=payload.amount,
        status=TransactionStatus.APPROVED,
        risk_score=10,
        risk_level=RiskLevel.LOW,
        device_fingerprint=payload.device_fingerprint,
        idempotency_key=payload.idempotency_key,
        receipt_no=receipt_num,
        related_account_id=locked_receiver.id,
        is_simulated=False
    )
    db.add(txn)
    await db.commit()

    return TransactionResponse(
        id=txn.id,
        account_id=txn.account_id,
        atm_id=txn.atm_id,
        type=txn.type,
        amount=txn.amount,
        status=txn.status,
        risk_score=txn.risk_score,
        risk_level=txn.risk_level,
        receipt_no=txn.receipt_no,
        new_balance=locked_sender.balance,
        created_at=txn.created_at
    )


@router.get("/{receipt_no}/receipt.pdf")
async def download_receipt_pdf(
    receipt_no: str,
    db: AsyncSession = Depends(get_db)
):
    """Generates and streams a downloadable PDF receipt for a transaction."""
    stmt = (
        select(Transaction, Atm, Account, Card)
        .join(Atm, Transaction.atm_id == Atm.id)
        .join(Account, Transaction.account_id == Account.id)
        .outerjoin(Card, Card.account_id == Account.id)
        .where(Transaction.receipt_no == receipt_no)
    )
    res = await db.execute(stmt)
    row = res.first()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Receipt reference not found.")

    txn, atm, account, card = row
    card_last4 = card.last4 if card else "9999"

    pdf_bytes = generate_pdf_receipt(
        receipt_no=txn.receipt_no,
        atm_code=atm.atm_code,
        atm_city=atm.city,
        account_number=account.account_number,
        card_last4=card_last4,
        txn_type=txn.type.value,
        amount=txn.amount,
        new_balance=account.balance,
        timestamp=txn.created_at,
        risk_level=txn.risk_level.value
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=receipt_{receipt_no}.pdf"}
    )
