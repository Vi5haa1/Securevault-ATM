from typing import Optional, List, Dict
from decimal import Decimal
import datetime
from pydantic import BaseModel, Field
from app.db.models.models import AtmStatus, NetworkStatus, SensorType, SensorState


class AtmSensorSchema(BaseModel):
    sensor_type: SensorType
    state: SensorState
    last_updated: datetime.datetime

    class Config:
        from_attributes = True


class AtmInventorySchema(BaseModel):
    denomination: int
    note_count: int

    class Config:
        from_attributes = True


class AtmResponse(BaseModel):
    id: int
    atm_code: str
    city: str
    address: str
    latitude: Decimal
    longitude: Decimal
    status: AtmStatus
    network_status: NetworkStatus
    cash_total: Decimal
    low_cash_threshold: Decimal
    security_status: str
    last_heartbeat: datetime.datetime
    sensors: List[AtmSensorSchema] = []
    inventories: List[AtmInventorySchema] = []

    class Config:
        from_attributes = True


class AtmCreateRequest(BaseModel):
    atm_code: str = Field(..., min_length=4, max_length=32)
    city: str = Field(..., min_length=2, max_length=64)
    address: str = Field(..., min_length=5, max_length=255)
    latitude: Decimal
    longitude: Decimal
    cash_total: Optional[Decimal] = Decimal("1000000.00")
    low_cash_threshold: Optional[Decimal] = Decimal("100000.00")


class CashLoadRequest(BaseModel):
    denominations: Dict[int, int]  # e.g. {100: 500, 200: 500, 500: 1000, 2000: 200}


class AtmStatusUpdateRequest(BaseModel):
    status: AtmStatus
    reason: Optional[str] = None


class SensorUpdateRequest(BaseModel):
    sensor_type: SensorType
    state: SensorState
    trigger_alert: bool = True
