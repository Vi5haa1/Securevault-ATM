import datetime
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete

from app.db.session import get_db
from app.db.models.models import DetectionRule, SeverityLevel, User
from app.core.deps import require_permission, get_current_user
from app.audit.writer import write_audit_log

router = APIRouter(prefix="/soc/rules", tags=["SOC Detection Rules"])


class RuleCreateRequest(BaseModel):
    rule_id: str = Field(..., example="RULE-SV-013")
    name: str
    description: str
    severity: SeverityLevel = SeverityLevel.HIGH
    event_types: List[str]
    conditions: Dict[str, Any]
    actions: List[str]
    cooldown_seconds: int = 60
    mitre_tactic: str = "Defense Evasion"
    mitre_technique: str = "T1550 - Alternate Auth"


class RuleUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[SeverityLevel] = None
    event_types: Optional[List[str]] = None
    conditions: Optional[Dict[str, Any]] = None
    actions: Optional[List[str]] = None
    cooldown_seconds: Optional[int] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    enabled: Optional[bool] = None


class RuleTestRequest(BaseModel):
    sample_event: Dict[str, Any]


@router.get("/")
async def list_detection_rules(
    enabled: Optional[bool] = None,
    severity: Optional[SeverityLevel] = None,
    current_user: User = Depends(require_permission("soc:dashboard")),
    db: AsyncSession = Depends(get_db)
):
    """Lists all database-backed detection rules with hit counts and metadata."""
    stmt = select(DetectionRule).order_by(DetectionRule.rule_id)
    if enabled is not None:
        stmt = stmt.where(DetectionRule.enabled == enabled)
    if severity is not None:
        stmt = stmt.where(DetectionRule.severity == severity)

    res = await db.execute(stmt)
    rules = res.scalars().all()
    return [
        {
            "id": r.id,
            "rule_id": r.rule_id,
            "name": r.name,
            "description": r.description,
            "enabled": r.enabled,
            "severity": r.severity.value,
            "event_types": r.event_types,
            "conditions": r.conditions,
            "actions": r.actions,
            "cooldown_seconds": r.cooldown_seconds,
            "mitre_tactic": r.mitre_tactic,
            "mitre_technique": r.mitre_technique,
            "version": r.version,
            "hit_count": r.hit_count,
            "last_hit_at": r.last_hit_at.isoformat() if r.last_hit_at else None,
            "updated_by": r.updated_by,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None
        }
        for r in rules
    ]


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_detection_rule(
    payload: RuleCreateRequest,
    current_user: User = Depends(require_permission("admin:users")),
    db: AsyncSession = Depends(get_db)
):
    """Creates a new editable detection rule (RBAC: Bank Admin / Super Admin)."""
    # Check duplicate
    stmt = select(DetectionRule).where(DetectionRule.rule_id == payload.rule_id)
    res = await db.execute(stmt)
    if res.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Rule ID '{payload.rule_id}' already exists.")

    rule = DetectionRule(
        rule_id=payload.rule_id,
        name=payload.name,
        description=payload.description,
        enabled=True,
        severity=payload.severity,
        event_types=payload.event_types,
        conditions=payload.conditions,
        actions=payload.actions,
        cooldown_seconds=payload.cooldown_seconds,
        mitre_tactic=payload.mitre_tactic,
        mitre_technique=payload.mitre_technique,
        version=1,
        hit_count=0,
        updated_by=current_user.username
    )
    db.add(rule)
    await db.flush()

    # Audit rule creation
    await write_audit_log(
        db=db,
        action="DETECTION_RULE_CREATED",
        resource_type="DETECTION_RULE",
        resource_id=rule.rule_id,
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        payload={"rule_id": rule.rule_id, "name": rule.name, "severity": rule.severity.value}
    )
    await db.commit()
    return {"status": "SUCCESS", "rule_id": rule.rule_id, "id": rule.id}


@router.put("/{rule_id}")
async def update_detection_rule(
    rule_id: str,
    payload: RuleUpdateRequest,
    current_user: User = Depends(require_permission("admin:users")),
    db: AsyncSession = Depends(get_db)
):
    """Updates an existing detection rule with version increment and before/after diff audit."""
    stmt = select(DetectionRule).where(DetectionRule.rule_id == rule_id)
    res = await db.execute(stmt)
    rule = res.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found.")

    before_state = {
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity.value,
        "event_types": rule.event_types,
        "conditions": rule.conditions,
        "actions": rule.actions,
        "enabled": rule.enabled,
        "version": rule.version
    }

    if payload.name is not None: rule.name = payload.name
    if payload.description is not None: rule.description = payload.description
    if payload.severity is not None: rule.severity = payload.severity
    if payload.event_types is not None: rule.event_types = payload.event_types
    if payload.conditions is not None: rule.conditions = payload.conditions
    if payload.actions is not None: rule.actions = payload.actions
    if payload.cooldown_seconds is not None: rule.cooldown_seconds = payload.cooldown_seconds
    if payload.mitre_tactic is not None: rule.mitre_tactic = payload.mitre_tactic
    if payload.mitre_technique is not None: rule.mitre_technique = payload.mitre_technique
    if payload.enabled is not None: rule.enabled = payload.enabled

    rule.version += 1
    rule.updated_by = current_user.username
    rule.updated_at = datetime.datetime.now(datetime.timezone.utc)

    after_state = {
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity.value,
        "event_types": rule.event_types,
        "conditions": rule.conditions,
        "actions": rule.actions,
        "enabled": rule.enabled,
        "version": rule.version
    }

    await write_audit_log(
        db=db,
        action="DETECTION_RULE_UPDATED",
        resource_type="DETECTION_RULE",
        resource_id=rule.rule_id,
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        payload={"rule_id": rule.rule_id, "diff": {"before": before_state, "after": after_state}}
    )
    await db.commit()
    return {"status": "SUCCESS", "rule_id": rule.rule_id, "version": rule.version}


@router.patch("/{rule_id}/toggle")
async def toggle_detection_rule(
    rule_id: str,
    current_user: User = Depends(require_permission("admin:users")),
    db: AsyncSession = Depends(get_db)
):
    """Toggles rule enabled/disabled state."""
    stmt = select(DetectionRule).where(DetectionRule.rule_id == rule_id)
    res = await db.execute(stmt)
    rule = res.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found.")

    rule.enabled = not rule.enabled
    rule.updated_by = current_user.username
    rule.updated_at = datetime.datetime.now(datetime.timezone.utc)

    await write_audit_log(
        db=db,
        action="DETECTION_RULE_TOGGLED",
        resource_type="DETECTION_RULE",
        resource_id=rule.rule_id,
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        payload={"rule_id": rule.rule_id, "new_state": rule.enabled}
    )
    await db.commit()
    return {"status": "SUCCESS", "rule_id": rule.rule_id, "enabled": rule.enabled}


@router.post("/{rule_id}/test")
async def dry_run_test_rule(
    rule_id: str,
    payload: RuleTestRequest,
    current_user: User = Depends(require_permission("soc:dashboard")),
    db: AsyncSession = Depends(get_db)
):
    """Dry-run evaluates a rule against sample event payload without saving or triggering real containment."""
    stmt = select(DetectionRule).where(DetectionRule.rule_id == rule_id)
    res = await db.execute(stmt)
    rule = res.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found.")

    ev = payload.sample_event
    event_type = ev.get("type", "")
    matches_event_type = event_type in rule.event_types

    cond = rule.conditions
    field = cond.get("field", "count")
    op = cond.get("op", ">=")
    threshold = cond.get("threshold", 1)

    value_in_event = ev.get(field, 0)
    matched = False
    if matches_event_type:
        if op == ">=" and value_in_event >= threshold:
            matched = True
        elif op == "==" and value_in_event == cond.get("value"):
            matched = True
        elif field == "immediate":
            matched = True

    return {
        "rule_id": rule.rule_id,
        "rule_name": rule.name,
        "sample_event_type": event_type,
        "type_matched": matches_event_type,
        "condition_evaluated": cond,
        "condition_matched": matched,
        "actions_that_would_execute": rule.actions if matched else [],
        "verdict": "TRIGGERED" if matched else "NO_MATCH"
    }
