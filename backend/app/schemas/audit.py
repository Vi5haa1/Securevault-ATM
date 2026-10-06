from typing import Optional, Dict, Any
import datetime
from pydantic import BaseModel


class AuditLogResponse(BaseModel):
    id: int
    sequence_no: int
    actor_id: Optional[str] = None
    actor_role: Optional[str] = None
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    payload: Dict[str, Any]
    ip_address: Optional[str] = None
    created_at: datetime.datetime
    prev_hash: str
    hash: str

    class Config:
        from_attributes = True


class AuditVerifyResponse(BaseModel):
    total_logs: int
    verified_logs: int
    tampered: bool
    broken_sequence_no: Optional[int] = None
    broken_log_id: Optional[int] = None
    status: str
    details: str
    verified_at: datetime.datetime


class TamperDemoRequest(BaseModel):
    log_id: int
    modified_action: str = "UNAUTHORIZED_TAMPER_TEST"
