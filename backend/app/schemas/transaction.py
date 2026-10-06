from typing import Optional, Dict, Any, List
from decimal import Decimal
import datetime
from pydantic import BaseModel, Field
from app.db.models.models import TransactionType, TransactionStatus, RiskLevel


class WithdrawalRequest(BaseModel):
    account_id: int
    atm_id: int
    amount: Decimal = Field(..., gt=0)
    device_fingerprint: Optional[str] = "web-kiosk-default"
    idempotency_key: str = Field(..., min_length=16, max_length=64)


class DepositRequest(BaseModel):
    account_id: int
    atm_id: int
    amount: Decimal = Field(..., gt=0)
    denominations: Dict[int, int]
    device_fingerprint: Optional[str] = "web-kiosk-default"
    idempotency_key: str = Field(..., min_length=16, max_length=64)


class TransferRequest(BaseModel):
    source_account_id: int
    destination_account_number: str = Field(..., min_length=6, max_length=20)
    atm_id: int
    amount: Decimal = Field(..., gt=0)
    device_fingerprint: Optional[str] = "web-kiosk-default"
    idempotency_key: str = Field(..., min_length=16, max_length=64)


class DenominationBreakdown(BaseModel):
    denomination: int
    count: int


class ZeroTrustStepTrace(BaseModel):
    step_name: str
    status: str  # "PASSED", "WARNING", "FAILED"
    details: str
    timestamp: datetime.datetime


class TransactionResponse(BaseModel):
    id: int
    account_id: int
    atm_id: int
    type: TransactionType
    amount: Decimal
    status: TransactionStatus
    risk_score: int
    risk_level: RiskLevel
    risk_factors: Optional[Dict[str, Any]] = None
    receipt_no: str
    dispensed_notes: Optional[List[DenominationBreakdown]] = None
    new_balance: Optional[Decimal] = None
    created_at: datetime.datetime
    zero_trust_trace: Optional[List[ZeroTrustStepTrace]] = None
    error_message: Optional[str] = None

    class Config:
        from_attributes = True
