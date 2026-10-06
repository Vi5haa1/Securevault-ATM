import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.db.models.models import (
    Incident, IncidentAction, IncidentNote, IncidentStatus, 
    SeverityLevel, User, UserRole, Atm, SecurityEvent
)
from app.schemas.incident import (
    IncidentResponse, IncidentStatusUpdateRequest, 
    IncidentNoteCreate, IncidentNoteResponse
)
from app.core.deps import require_permission, get_current_user
from app.audit.writer import write_audit_log
import hashlib
import json

router = APIRouter(prefix="/incidents", tags=["Incident Management"])


@router.get("", response_model=List[IncidentResponse])
async def list_incidents(
    status_filter: Optional[IncidentStatus] = None,
    severity: Optional[SeverityLevel] = None,
    limit: int = Query(50, le=200),
    current_user: User = Depends(require_permission("soc:incidents")),
    db: AsyncSession = Depends(get_db)
):
    """Lists security incidents with optional status and severity filtering."""
    stmt = (
        select(Incident)
        .options(selectinload(Incident.actions), selectinload(Incident.notes))
        .order_by(Incident.created_at.desc())
        .limit(limit)
    )
    if status_filter:
        stmt = stmt.where(Incident.status == status_filter)
    if severity:
        stmt = stmt.where(Incident.severity == severity)

    res = await db.execute(stmt)
    return res.scalars().all()


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: int,
    current_user: User = Depends(require_permission("soc:incidents")),
    db: AsyncSession = Depends(get_db)
):
    """Retrieves full incident dossier including automated playbook checklist, analyst notes, and linked events."""
    stmt = (
        select(Incident)
        .options(selectinload(Incident.actions), selectinload(Incident.notes))
        .where(Incident.id == incident_id)
    )
    res = await db.execute(stmt)
    incident = res.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident record not found.")

    # Load linked events
    ev_stmt = select(SecurityEvent).where(SecurityEvent.incident_id == incident.id).order_by(SecurityEvent.created_at.desc())
    ev_res = await db.execute(ev_stmt)
    events = ev_res.scalars().all()

    # Load ATM details if attached
    atm_data = None
    if incident.atm_id:
        atm_stmt = select(Atm).where(Atm.id == incident.atm_id)
        atm_res = await db.execute(atm_stmt)
        atm = atm_res.scalar_one_or_none()
        if atm:
            atm_data = {
                "id": atm.id,
                "atm_code": atm.atm_code,
                "city": atm.city,
                "status": atm.status.value if hasattr(atm.status, "value") else str(atm.status),
                "is_locked_down": atm.is_locked_down,
                "tamper_detected": atm.tamper_detected,
                "firmware_version": atm.firmware_version,
                "firmware_status": atm.firmware_status,
                "certificate_status": atm.certificate_status,
                "cpu_usage": atm.cpu_usage,
                "network_latency_ms": atm.network_latency_ms,
                "cash_level_percentage": atm.cash_level_percentage,
                "active_risk_score": atm.active_risk_score,
            }

    serialized_events = [
        {
            "id": e.id,
            "type": e.type,
            "severity": e.severity.value if hasattr(e.severity, "value") else str(e.severity),
            "source": e.source,
            "ip_address": e.ip_address,
            "created_at": e.created_at.isoformat() if e.created_at else None,
            "details": e.details or {},
            "mitre_technique": e.mitre_technique,
            "mitre_tactic": e.mitre_tactic,
            "rule_id": e.rule_id
        }
        for e in events
    ]

    # Convert notes
    serialized_notes = [
        IncidentNoteResponse(
            id=n.id,
            author_id=n.author_id,
            author_name="Analyst",
            text=n.text,
            created_at=n.created_at
        )
        for n in incident.notes
    ]

    return IncidentResponse(
        id=incident.id,
        incident_code=incident.incident_code,
        severity=incident.severity,
        threat_type=incident.threat_type,
        atm_id=incident.atm_id,
        account_id=incident.account_id,
        status=incident.status,
        assigned_analyst_id=incident.assigned_analyst_id,
        summary=incident.summary,
        created_at=incident.created_at,
        resolved_at=incident.resolved_at,
        is_simulated=incident.is_simulated,
        actions=[IncidentActionResponse.from_orm(a) for a in incident.actions],
        notes=serialized_notes,
        events=serialized_events,
        atm_details=atm_data
    )


@router.post("/{incident_id}/status", response_model=IncidentResponse)
async def update_incident_status(
    incident_id: int,
    payload: IncidentStatusUpdateRequest,
    current_user: User = Depends(require_permission("soc:incidents")),
    db: AsyncSession = Depends(get_db)
):
    """Updates incident status (OPEN -> INVESTIGATING -> CONTAINED -> RESOLVED) and assignment."""
    stmt = (
        select(Incident)
        .options(selectinload(Incident.actions), selectinload(Incident.notes))
        .where(Incident.id == incident_id)
    )
    res = await db.execute(stmt)
    incident = res.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")

    old_status = incident.status.value
    incident.status = payload.status
    if payload.assigned_analyst_id:
        incident.assigned_analyst_id = payload.assigned_analyst_id
    elif not incident.assigned_analyst_id:
        incident.assigned_analyst_id = current_user.id

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    if payload.status == IncidentStatus.RESOLVED:
        incident.resolved_at = now_utc

    if payload.resolution_note:
        note = IncidentNote(
            incident_id=incident.id,
            author_id=current_user.id,
            text=f"Status changed to {payload.status.value}: {payload.resolution_note}"
        )
        db.add(note)
        incident.notes.append(note)

    await write_audit_log(
        db=db,
        action="INCIDENT_STATUS_UPDATED",
        resource_type="INCIDENT",
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        resource_id=incident.incident_code,
        payload={"old_status": old_status, "new_status": payload.status.value}
    )

    await db.commit()
    await db.refresh(incident)
    return incident


@router.post("/{incident_id}/notes", response_model=IncidentNoteResponse)
async def add_incident_note(
    incident_id: int,
    payload: IncidentNoteCreate,
    current_user: User = Depends(require_permission("soc:incidents")),
    db: AsyncSession = Depends(get_db)
):
    """Adds an analyst investigative note to an incident dossier."""
    stmt = select(Incident).where(Incident.id == incident_id)
    res = await db.execute(stmt)
    incident = res.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")

    note = IncidentNote(
        incident_id=incident.id,
        author_id=current_user.id,
        text=payload.text
    )
    db.add(note)
    await db.commit()
    await db.refresh(note)

    return IncidentNoteResponse(
        id=note.id,
        author_id=note.author_id,
        author_name=current_user.username,
        text=note.text,
        created_at=note.created_at
    )


@router.get("/{incident_id}/export")
async def export_incident_report(
    incident_id: int,
    current_user: User = Depends(require_permission("soc:incidents")),
    db: AsyncSession = Depends(get_db)
):
    """Exports an immutable cryptographically hashed forensic report of the incident."""
    stmt = (
        select(Incident)
        .options(selectinload(Incident.actions), selectinload(Incident.notes))
        .where(Incident.id == incident_id)
    )
    res = await db.execute(stmt)
    incident = res.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")

    ev_stmt = select(SecurityEvent).where(SecurityEvent.incident_id == incident.id).order_by(SecurityEvent.created_at.asc())
    ev_res = await db.execute(ev_stmt)
    events = ev_res.scalars().all()

    report_payload = {
        "incident_code": incident.incident_code,
        "threat_type": incident.threat_type,
        "severity": incident.severity.value if hasattr(incident.severity, "value") else str(incident.severity),
        "status": incident.status.value if hasattr(incident.status, "value") else str(incident.status),
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        "summary": incident.summary,
        "is_simulated": incident.is_simulated,
        "playbook_actions": [
            {"action": a.action_type, "result": a.result, "time": a.created_at.isoformat()}
            for a in incident.actions
        ],
        "notes": [
            {"author_id": n.author_id, "text": n.text, "time": n.created_at.isoformat()}
            for n in incident.notes
        ],
        "events": [
            {"id": e.id, "type": e.type, "severity": e.severity.value, "time": e.created_at.isoformat(), "source": e.source}
            for e in events
        ]
    }
    canonical_repr = json.dumps(report_payload, sort_keys=True)
    evidence_hash = hashlib.sha256(canonical_repr.encode()).hexdigest()

    await write_audit_log(
        db=db,
        action="INCIDENT_REPORT_EXPORTED",
        resource_type="INCIDENT",
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        resource_id=incident.incident_code,
        payload={"evidence_sha256": evidence_hash}
    )
    await db.commit()

    return {
        "report": report_payload,
        "evidence_sha256": evidence_hash,
        "exported_by": current_user.username,
        "exported_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }
