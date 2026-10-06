from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class SimulationRequest(BaseModel):
    simulation_type: str = Field(..., description="BRUTE_FORCE | SUSPICIOUS_TXN | ATM_TAMPER | API_ABUSE | UNAUTHORIZED_ACCESS | SESSION_ABUSE")
    atm_id: Optional[int] = None
    account_id: Optional[int] = None
    intensity: Optional[int] = 1


class SimulationStepResult(BaseModel):
    step: str
    status: str
    detail: str


class SimulationResultResponse(BaseModel):
    simulation_id: str
    simulation_type: str
    threat_detected: bool
    detection_rule: str
    actions_triggered: List[str]
    incident_code: Optional[str] = None
    alert_title: Optional[str] = None
    steps: List[SimulationStepResult]
    pipeline_trace: Optional[List[Dict[str, Any]]] = None
