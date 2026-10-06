from typing import List, Dict, Any, Optional
from decimal import Decimal
import datetime
from pydantic import BaseModel
from app.db.models.models import RiskLevel


class RiskFactorDetail(BaseModel):
    factor_name: str
    points: int
    triggered: bool
    description: str


class RiskAssessmentResponse(BaseModel):
    total_score: int
    risk_level: RiskLevel
    recommended_action: str
    factors: List[RiskFactorDetail]


class BehaviorProfileResponse(BaseModel):
    customer_id: int
    avg_withdrawal: Decimal
    std_withdrawal: Decimal
    typical_min: Decimal
    typical_max: Decimal
    typical_start_hour: int
    typical_end_hour: int
    typical_cities: List[str]
    txn_per_week_avg: Decimal
    updated_at: datetime.datetime

    class Config:
        from_attributes = True
