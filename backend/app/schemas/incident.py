from typing import Optional, List, Dict, Any
import datetime
from pydantic import BaseModel, Field
from app.db.models.models import SeverityLevel, IncidentStatus, AlertStatus


class AlertResponse(BaseModel):
    id: int
    event_id: int
    severity: SeverityLevel
    title: str
    message: str
    status: AlertStatus
    created_at: datetime.datetime

    class Config:
        from_attributes = True


class IncidentActionResponse(BaseModel):
    id: int
    action_type: str
    result: str
    created_at: datetime.datetime

    class Config:
        from_attributes = True


class IncidentNoteCreate(BaseModel):
    text: str = Field(..., min_length=3, max_length=2000)


class IncidentNoteResponse(BaseModel):
    id: int
    author_id: int
    author_name: Optional[str] = None
    text: str
    created_at: datetime.datetime

    class Config:
        from_attributes = True


class IncidentResponse(BaseModel):
    id: int
    incident_code: str
    severity: SeverityLevel
    threat_type: str
    atm_id: Optional[int] = None
    account_id: Optional[int] = None
    status: IncidentStatus
    assigned_analyst_id: Optional[int] = None
    summary: str
    created_at: datetime.datetime
    resolved_at: Optional[datetime.datetime] = None
    is_simulated: bool
    actions: List[IncidentActionResponse] = []
    notes: List[IncidentNoteResponse] = []
    events: Optional[List[Dict[str, Any]]] = None
    atm_details: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


class IncidentStatusUpdateRequest(BaseModel):
    status: IncidentStatus
    assigned_analyst_id: Optional[int] = None
    resolution_note: Optional[str] = None
