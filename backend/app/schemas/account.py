from typing import Optional, List
from decimal import Decimal
import datetime
from pydantic import BaseModel, Field
from app.db.models.models import AccountType, AccountStatus, CardStatus


class CardResponse(BaseModel):
    id: int
    last4: str
    status: CardStatus
    expiry: str
    pin_failed_attempts: int

    class Config:
        from_attributes = True


class AccountResponse(BaseModel):
    id: int
    account_number: str
    type: AccountType
    balance: Decimal
    currency: str
    status: AccountStatus
    daily_withdrawal_limit: Decimal
    per_txn_limit: Decimal
    cards: List[CardResponse] = []

    class Config:
        from_attributes = True


class BalanceInquiryResponse(BaseModel):
    account_number: str
    balance: Decimal
    currency: str
    available_balance: Decimal
    daily_limit_remaining: Decimal
    atm_code: str


class MiniStatementItem(BaseModel):
    id: int
    type: str
    amount: Decimal
    status: str
    created_at: datetime.datetime
    receipt_no: str
    description: str


class MiniStatementResponse(BaseModel):
    account_number: str
    current_balance: Decimal
    currency: str
    transactions: List[MiniStatementItem]
