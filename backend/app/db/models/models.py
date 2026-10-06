import datetime
import enum
from typing import Optional, List, Dict, Any
from decimal import Decimal
from sqlalchemy import (
    String, Integer, BigInteger, Boolean, Numeric, DateTime, ForeignKey, 
    Text, Enum, func, Index, JSON
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin


class UserRole(str, enum.Enum):
    CUSTOMER = "CUSTOMER"
    ATM_OPERATOR = "ATM_OPERATOR"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    BANK_ADMIN = "BANK_ADMIN"
    SUPER_ADMIN = "SUPER_ADMIN"


class AccountType(str, enum.Enum):
    SAVINGS = "SAVINGS"
    CURRENT = "CURRENT"


class AccountStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    LOCKED = "LOCKED"
    DISABLED = "DISABLED"


class CardStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    LOCKED = "LOCKED"
    EXPIRED = "EXPIRED"
    BLOCKED = "BLOCKED"


class AtmStatus(str, enum.Enum):
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    MAINTENANCE = "MAINTENANCE"
    LOCKDOWN = "LOCKDOWN"
    DISABLED = "DISABLED"


class NetworkStatus(str, enum.Enum):
    CONNECTED = "CONNECTED"
    DEGRADED = "DEGRADED"
    DISCONNECTED = "DISCONNECTED"


class SensorType(str, enum.Enum):
    CARD_READER = "CARD_READER"
    PIN_PAD = "PIN_PAD"
    CASH_DISPENSER = "CASH_DISPENSER"
    DOOR = "DOOR"
    CAMERA = "CAMERA"
    TAMPER = "TAMPER"
    NETWORK = "NETWORK"


class SensorState(str, enum.Enum):
    NORMAL = "NORMAL"
    WARNING = "WARNING"
    ALERT = "ALERT"


class TransactionType(str, enum.Enum):
    WITHDRAWAL = "WITHDRAWAL"
    DEPOSIT = "DEPOSIT"
    TRANSFER = "TRANSFER"
    BALANCE = "BALANCE"
    MINI_STATEMENT = "MINI_STATEMENT"
    PIN_CHANGE = "PIN_CHANGE"


class TransactionStatus(str, enum.Enum):
    APPROVED = "APPROVED"
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class RiskLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SeverityLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, enum.Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"


class AlertStatus(str, enum.Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    CLOSED = "CLOSED"


# -------------------------------------------------------------
# Core Identity Models
# -------------------------------------------------------------

class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    phone: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.CUSTOMER, nullable=False, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    locked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_login_at: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    customer: Mapped[Optional["Customer"]] = relationship("Customer", back_populates="user", uselist=False, cascade="all, delete-orphan")
    sessions: Mapped[List["UserSession"]] = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    notifications: Mapped[List["Notification"]] = relationship("Notification", back_populates="user", cascade="all, delete-orphan")


class Customer(Base, TimestampMixin):
    __tablename__ = "customers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(128), nullable=False)
    home_city: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="customer")
    accounts: Mapped[List["Account"]] = relationship("Account", back_populates="customer", cascade="all, delete-orphan")
    trusted_devices: Mapped[List["TrustedDevice"]] = relationship("TrustedDevice", back_populates="customer", cascade="all, delete-orphan")
    behavior_profile: Mapped[Optional["BehaviorProfile"]] = relationship("BehaviorProfile", back_populates="customer", uselist=False, cascade="all, delete-orphan")


class TrustedDevice(Base, TimestampMixin):
    __tablename__ = "trusted_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    customer_id: Mapped[int] = mapped_column(Integer, ForeignKey("customers.id", ondelete="CASCADE"), index=True, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    first_seen: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    trusted: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    customer: Mapped["Customer"] = relationship("Customer", back_populates="trusted_devices")

    __table_args__ = (
        Index("ix_trusted_devices_cust_fp", "customer_id", "fingerprint"),
    )


# -------------------------------------------------------------
# Banking Accounts & Cards
# -------------------------------------------------------------

class Account(Base, TimestampMixin):
    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    customer_id: Mapped[int] = mapped_column(Integer, ForeignKey("customers.id", ondelete="CASCADE"), index=True, nullable=False)
    account_number: Mapped[str] = mapped_column(String(20), unique=True, index=True, nullable=False)
    type: Mapped[AccountType] = mapped_column(Enum(AccountType), default=AccountType.SAVINGS, nullable=False)
    balance: Mapped[Decimal] = mapped_column(Numeric(14, 2), default=Decimal("0.00"), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), default="INR", nullable=False)
    status: Mapped[AccountStatus] = mapped_column(Enum(AccountStatus), default=AccountStatus.ACTIVE, nullable=False, index=True)
    daily_withdrawal_limit: Mapped[Decimal] = mapped_column(Numeric(10, 2), default=Decimal("40000.00"), nullable=False)
    per_txn_limit: Mapped[Decimal] = mapped_column(Numeric(10, 2), default=Decimal("20000.00"), nullable=False)

    customer: Mapped["Customer"] = relationship("Customer", back_populates="accounts")
    cards: Mapped[List["Card"]] = relationship("Card", back_populates="account", cascade="all, delete-orphan")
    transactions: Mapped[List["Transaction"]] = relationship(
        "Transaction", 
        back_populates="account", 
        foreign_keys="Transaction.account_id",
        cascade="all, delete-orphan"
    )


class Card(Base, TimestampMixin):
    __tablename__ = "cards"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id: Mapped[int] = mapped_column(Integer, ForeignKey("accounts.id", ondelete="CASCADE"), index=True, nullable=False)
    card_number_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    last4: Mapped[str] = mapped_column(String(4), nullable=False)
    pin_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    pin_failed_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[CardStatus] = mapped_column(Enum(CardStatus), default=CardStatus.ACTIVE, nullable=False, index=True)
    expiry: Mapped[str] = mapped_column(String(5), nullable=False)  # MM/YY
    pin_changed_at: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    account: Mapped["Account"] = relationship("Account", back_populates="cards")


# -------------------------------------------------------------
# ATM Infrastructure & Sensors
# -------------------------------------------------------------

class Atm(Base, TimestampMixin):
    __tablename__ = "atms"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    atm_code: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    city: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    address: Mapped[str] = mapped_column(String(255), nullable=False)
    latitude: Mapped[Decimal] = mapped_column(Numeric(9, 6), nullable=False)
    longitude: Mapped[Decimal] = mapped_column(Numeric(9, 6), nullable=False)
    status: Mapped[AtmStatus] = mapped_column(Enum(AtmStatus), default=AtmStatus.ONLINE, nullable=False, index=True)
    network_status: Mapped[NetworkStatus] = mapped_column(Enum(NetworkStatus), default=NetworkStatus.CONNECTED, nullable=False)
    cash_total: Mapped[Decimal] = mapped_column(Numeric(14, 2), default=Decimal("0.00"), nullable=False)
    low_cash_threshold: Mapped[Decimal] = mapped_column(Numeric(14, 2), default=Decimal("100000.00"), nullable=False)
    security_status: Mapped[str] = mapped_column(String(32), default="SECURE", nullable=False)
    firmware_version: Mapped[str] = mapped_column(String(32), default="SV-ATM-FW-3.4.1", nullable=False)
    firmware_hash: Mapped[str] = mapped_column(String(64), default="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", nullable=False)
    secure_boot_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    certificate_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    certificate_status: Mapped[str] = mapped_column(String(32), default="VALID", nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    latency_ms: Mapped[int] = mapped_column(Integer, default=24, nullable=False)
    cpu_usage: Mapped[int] = mapped_column(Integer, default=18, nullable=False)
    memory_usage: Mapped[int] = mapped_column(Integer, default=32, nullable=False)
    disk_usage: Mapped[int] = mapped_column(Integer, default=45, nullable=False)
    under_attack: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_heartbeat: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    inventories: Mapped[List["AtmCashInventory"]] = relationship("AtmCashInventory", back_populates="atm", cascade="all, delete-orphan")
    sensors: Mapped[List["AtmSensor"]] = relationship("AtmSensor", back_populates="atm", cascade="all, delete-orphan")
    transactions: Mapped[List["Transaction"]] = relationship("Transaction", back_populates="atm")


class AtmCashInventory(Base, TimestampMixin):
    __tablename__ = "atm_cash_inventories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    atm_id: Mapped[int] = mapped_column(Integer, ForeignKey("atms.id", ondelete="CASCADE"), index=True, nullable=False)
    denomination: Mapped[int] = mapped_column(Integer, nullable=False)  # 100, 200, 500, 2000
    note_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    atm: Mapped["Atm"] = relationship("Atm", back_populates="inventories")

    __table_args__ = (
        Index("ix_atm_denomination", "atm_id", "denomination", unique=True),
    )


class AtmSensor(Base):
    __tablename__ = "atm_sensors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    atm_id: Mapped[int] = mapped_column(Integer, ForeignKey("atms.id", ondelete="CASCADE"), index=True, nullable=False)
    sensor_type: Mapped[SensorType] = mapped_column(Enum(SensorType), nullable=False)
    state: Mapped[SensorState] = mapped_column(Enum(SensorState), default=SensorState.NORMAL, nullable=False)
    last_updated: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )

    atm: Mapped["Atm"] = relationship("Atm", back_populates="sensors")

    __table_args__ = (
        Index("ix_atm_sensor_type", "atm_id", "sensor_type", unique=True),
    )


# -------------------------------------------------------------
# Transactions & Risk
# -------------------------------------------------------------

class Transaction(Base, TimestampMixin):
    __tablename__ = "transactions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id: Mapped[int] = mapped_column(Integer, ForeignKey("accounts.id"), index=True, nullable=False)
    atm_id: Mapped[int] = mapped_column(Integer, ForeignKey("atms.id"), index=True, nullable=False)
    type: Mapped[TransactionType] = mapped_column(Enum(TransactionType), nullable=False, index=True)
    amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), default=Decimal("0.00"), nullable=False)
    status: Mapped[TransactionStatus] = mapped_column(Enum(TransactionStatus), default=TransactionStatus.APPROVED, nullable=False, index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_level: Mapped[RiskLevel] = mapped_column(Enum(RiskLevel), default=RiskLevel.LOW, nullable=False, index=True)
    risk_factors: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    device_fingerprint: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    receipt_no: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    related_account_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("accounts.id"), nullable=True)
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    iso_mti: Mapped[str] = mapped_column(String(8), default="0200", nullable=False)
    iso_stan: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    emv_atc: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    mac_digest: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    prev_txn_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    txn_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    account: Mapped["Account"] = relationship("Account", back_populates="transactions", foreign_keys=[account_id])
    atm: Mapped["Atm"] = relationship("Atm", back_populates="transactions")
    related_account: Mapped[Optional["Account"]] = relationship("Account", foreign_keys=[related_account_id])

    __table_args__ = (
        Index("ix_txn_account_time", "account_id", "created_at"),
        Index("ix_txn_atm_time", "atm_id", "created_at"),
    )


class BehaviorProfile(Base):
    __tablename__ = "behavior_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    customer_id: Mapped[int] = mapped_column(Integer, ForeignKey("customers.id", ondelete="CASCADE"), unique=True, index=True, nullable=False)
    avg_withdrawal: Mapped[Decimal] = mapped_column(Numeric(10, 2), default=Decimal("2000.00"), nullable=False)
    std_withdrawal: Mapped[Decimal] = mapped_column(Numeric(10, 2), default=Decimal("1000.00"), nullable=False)
    typical_min: Mapped[Decimal] = mapped_column(Numeric(10, 2), default=Decimal("500.00"), nullable=False)
    typical_max: Mapped[Decimal] = mapped_column(Numeric(10, 2), default=Decimal("5000.00"), nullable=False)
    typical_start_hour: Mapped[int] = mapped_column(Integer, default=7, nullable=False)   # 7 AM
    typical_end_hour: Mapped[int] = mapped_column(Integer, default=22, nullable=False)   # 10 PM
    typical_cities: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    txn_per_week_avg: Mapped[Decimal] = mapped_column(Numeric(5, 2), default=Decimal("3.50"), nullable=False)
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )

    customer: Mapped["Customer"] = relationship("Customer", back_populates="behavior_profile")


# -------------------------------------------------------------
# Security Events, Alerts & Incidents
# -------------------------------------------------------------

class SecurityEvent(Base, TimestampMixin):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    severity: Mapped[SeverityLevel] = mapped_column(Enum(SeverityLevel), default=SeverityLevel.LOW, nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    atm_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("atms.id", ondelete="SET NULL"), nullable=True, index=True)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    account_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("accounts.id", ondelete="SET NULL"), nullable=True, index=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    details: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    correlation_key: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    mitre_tactic: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    incident_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    rule_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    device_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)

    alerts: Mapped[List["Alert"]] = relationship("Alert", back_populates="event", cascade="all, delete-orphan")


class Alert(Base, TimestampMixin):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[int] = mapped_column(Integer, ForeignKey("security_events.id", ondelete="CASCADE"), index=True, nullable=False)
    severity: Mapped[SeverityLevel] = mapped_column(Enum(SeverityLevel), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(128), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[AlertStatus] = mapped_column(Enum(AlertStatus), default=AlertStatus.NEW, nullable=False, index=True)

    event: Mapped["SecurityEvent"] = relationship("SecurityEvent", back_populates="alerts")


class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_code: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    severity: Mapped[SeverityLevel] = mapped_column(Enum(SeverityLevel), nullable=False, index=True)
    threat_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    atm_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("atms.id", ondelete="SET NULL"), nullable=True, index=True)
    account_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("accounts.id", ondelete="SET NULL"), nullable=True, index=True)
    status: Mapped[IncidentStatus] = mapped_column(Enum(IncidentStatus), default=IncidentStatus.OPEN, nullable=False, index=True)
    assigned_analyst_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    resolved_at: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)

    actions: Mapped[List["IncidentAction"]] = relationship("IncidentAction", back_populates="incident", cascade="all, delete-orphan")
    notes: Mapped[List["IncidentNote"]] = relationship("IncidentNote", back_populates="incident", cascade="all, delete-orphan")


class IncidentAction(Base):
    __tablename__ = "incident_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    result: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), 
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        server_default=func.now(), 
        nullable=False
    )

    incident: Mapped["Incident"] = relationship("Incident", back_populates="actions")


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), 
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        server_default=func.now(), 
        nullable=False
    )

    incident: Mapped["Incident"] = relationship("Incident", back_populates="notes")


# -------------------------------------------------------------
# Security Policy & Audit Log
# -------------------------------------------------------------

class SecurityPolicy(Base):
    __tablename__ = "security_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    value: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=False)
    updated_by: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sequence_no: Mapped[int] = mapped_column(BigInteger, unique=True, index=True, nullable=False)
    actor_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    actor_role: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    action: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    resource_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    payload: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        server_default=func.now(),
        index=True,
        nullable=False
    )
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)


# -------------------------------------------------------------
# Notifications & Ephemeral Security
# -------------------------------------------------------------

class Notification(Base, TimestampMixin):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(128), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[SeverityLevel] = mapped_column(Enum(SeverityLevel), default=SeverityLevel.LOW, nullable=False)
    read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="notifications")


class OtpChallenge(Base):
    __tablename__ = "otp_challenges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    card_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("cards.id", ondelete="CASCADE"), nullable=True)
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    purpose: Mapped[str] = mapped_column(String(32), default="ATM_VERIFICATION", nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        server_default=func.now(),
        nullable=False
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    family_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    device_fingerprint: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        server_default=func.now(),
        nullable=False
    )


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_token: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    card_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("cards.id", ondelete="SET NULL"), nullable=True)
    atm_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("atms.id", ondelete="SET NULL"), nullable=True)
    started_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        server_default=func.now(),
        nullable=False
    )
    last_activity_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        server_default=func.now(),
        nullable=False
    )
    terminated_at: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    termination_reason: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="sessions")


# -------------------------------------------------------------
# Detection Rule Engine Models
# -------------------------------------------------------------

class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)  # e.g. RULE-SV-001
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    severity: Mapped[SeverityLevel] = mapped_column(Enum(SeverityLevel), default=SeverityLevel.HIGH, nullable=False)
    event_types: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    conditions: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    actions: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    cooldown_seconds: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    mitre_tactic: Mapped[str] = mapped_column(String(64), default="Initial Access", nullable=False)
    mitre_technique: Mapped[str] = mapped_column(String(64), default="T1110 - Brute Force", nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    hit_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_hit_at: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_by: Mapped[str] = mapped_column(String(64), default="SYSTEM", nullable=False)
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )


# -------------------------------------------------------------
# PKI & Digital Certificates
# -------------------------------------------------------------

class Certificate(Base, TimestampMixin):
    __tablename__ = "certificates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cert_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    subject: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    issuer: Mapped[str] = mapped_column(String(128), default="SecureVault Internal Root CA", nullable=False)
    serial_number: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    valid_from: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="VALID", index=True, nullable=False)  # VALID, EXPIRING, EXPIRED, REVOKED
    revocation_reason: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    private_key_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    atm_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("atms.id", ondelete="SET NULL"), nullable=True)


# -------------------------------------------------------------
# HSM Simulator & Cryptographic Keys
# -------------------------------------------------------------

class HsmKey(Base, TimestampMixin):
    __tablename__ = "hsm_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    purpose: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE", index=True, nullable=False)  # ACTIVE, ROTATING, EXPIRED, REVOKED
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    key_material_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    usage_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class KeyUsageAudit(Base):
    __tablename__ = "key_usage_audits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)  # ENCRYPT, DECRYPT, SIGN, VERIFY, ROTATE
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    resource: Mapped[str] = mapped_column(String(128), nullable=False)
    timestamp: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        server_default=func.now(),
        nullable=False
    )
    success: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


# -------------------------------------------------------------
# Synthetic Threat Intelligence
# -------------------------------------------------------------

class ThreatIndicator(Base, TimestampMixin):
    __tablename__ = "threat_indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    indicator_type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)  # IP, DOMAIN, HASH
    value: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    threat_category: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=80, nullable=False)
    severity: Mapped[SeverityLevel] = mapped_column(Enum(SeverityLevel), default=SeverityLevel.HIGH, nullable=False)
    first_seen: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=func.now(), nullable=False)
    last_seen: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=func.now(), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)
    tags: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)


# -------------------------------------------------------------
# API Inventory & Security Telemetry
# -------------------------------------------------------------

class ApiEndpoint(Base):
    __tablename__ = "api_endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    path: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    method: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    auth_required: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    required_role: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    rate_limit: Mapped[str] = mapped_column(String(32), default="60/min", nullable=False)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    shadow: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_seen: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        server_default=func.now(),
        nullable=False
    )

    __table_args__ = (
        Index("ix_api_path_method", "path", "method", unique=True),
    )


# -------------------------------------------------------------
# Audit Verification History
# -------------------------------------------------------------

class AuditVerificationHistory(Base):
    __tablename__ = "audit_verification_histories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        server_default=func.now(),
        nullable=False
    )
    total_records: Mapped[int] = mapped_column(Integer, nullable=False)
    verified_records: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    broken_index: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    details: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

