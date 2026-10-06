import datetime
from decimal import Decimal
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from sqlalchemy.orm import selectinload
import pandas as pd
import numpy as np

from app.db.session import get_db
from app.db.models.models import (
    Atm, AtmStatus, Transaction, TransactionStatus, TransactionType,
    Alert, AlertStatus, Incident, IncidentStatus, SecurityEvent,
    AuditLog, UserSession, User, SeverityLevel
)
from app.core.deps import require_permission, get_current_user
from app.audit.verifier import verify_audit_chain

router = APIRouter(prefix="/soc", tags=["SOC / SIEM Operations"])


@router.get("/kpis")
async def get_soc_kpis(
    current_user: User = Depends(require_permission("soc:dashboard")),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """Returns real-time executive and operational security KPIs for the SOC dashboard."""
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    start_of_day = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)

    # 1. ATM counts by status
    stmt_atms = select(Atm.status, func.count(Atm.id)).group_by(Atm.status)
    res_atms = await db.execute(stmt_atms)
    atm_counts = {status.value: 0 for status in AtmStatus}
    for st, count in res_atms.all():
        atm_counts[st.value] = count

    # 2. Active sessions
    stmt_sess = select(func.count(UserSession.id)).where(UserSession.terminated_at.is_(None))
    res_sess = await db.execute(stmt_sess)
    active_sessions = res_sess.scalar() or 0

    # 3. Transactions today
    stmt_tx = select(
        func.count(Transaction.id),
        func.sum(Transaction.amount)
    ).where(Transaction.created_at >= start_of_day)
    res_tx = await db.execute(stmt_tx)
    tx_count, tx_volume = res_tx.first() or (0, Decimal("0.00"))

    # 4. Alerts count by severity
    stmt_alerts = select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    res_alerts = await db.execute(stmt_alerts)
    alert_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for sev, count in res_alerts.all():
        alert_counts[sev.value] = count

    # 5. Incidents count by status
    stmt_inc = select(Incident.status, func.count(Incident.id)).group_by(Incident.status)
    res_inc = await db.execute(stmt_inc)
    incident_counts = {st.value: 0 for st in IncidentStatus}
    for st, count in res_inc.all():
        incident_counts[st.value] = count

    # 6. Cryptographic Audit Chain verification status
    audit_summary = await verify_audit_chain(db)

    return {
        "atms": {
            "total": sum(atm_counts.values()),
            "online": atm_counts.get("ONLINE", 0),
            "offline": atm_counts.get("OFFLINE", 0),
            "maintenance": atm_counts.get("MAINTENANCE", 0),
            "lockdown": atm_counts.get("LOCKDOWN", 0),
        },
        "active_sessions": active_sessions,
        "today_activity": {
            "transactions_count": tx_count or 0,
            "volume_inr": float(tx_volume or Decimal("0.00")),
        },
        "alerts": alert_counts,
        "incidents": {
            "open": incident_counts.get("OPEN", 0),
            "investigating": incident_counts.get("INVESTIGATING", 0),
            "contained": incident_counts.get("CONTAINED", 0),
            "resolved": incident_counts.get("RESOLVED", 0),
        },
        "audit_integrity": {
            "status": audit_summary["status"],
            "total_logs": audit_summary["total_logs"],
            "verified_logs": audit_summary["verified_logs"],
            "tampered": audit_summary["tampered"],
        }
    }


@router.get("/map")
async def get_atm_map(
    current_user: User = Depends(require_permission("soc:dashboard")),
    db: AsyncSession = Depends(get_db)
) -> List[Dict[str, Any]]:
    """Returns ATM geographic coordinates, operational health, firmware, certificates, and telemetry."""
    stmt = select(Atm).options(selectinload(Atm.sensors), selectinload(Atm.inventories))
    res = await db.execute(stmt)
    atms = res.scalars().all()

    # Pre-fetch open incidents by atm_id
    stmt_inc = select(Incident.atm_id, func.count(Incident.id)).where(
        and_(Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING]), Incident.atm_id.isnot(None))
    ).group_by(Incident.atm_id)
    res_inc = await db.execute(stmt_inc)
    open_incidents_map = dict(res_inc.all())

    # Pre-fetch active alerts by atm_id from SecurityEvent
    stmt_alr = select(SecurityEvent.atm_id, func.count(Alert.id)).join(Alert, Alert.event_id == SecurityEvent.id).where(
        and_(Alert.status == AlertStatus.NEW, SecurityEvent.atm_id.isnot(None))
    ).group_by(SecurityEvent.atm_id)
    res_alr = await db.execute(stmt_alr)
    active_alerts_map = dict(res_alr.all())

    map_nodes = []
    for atm in atms:
        sensor_dict = {s.sensor_type.value: s.state.value for s in atm.sensors}
        has_critical = (open_incidents_map.get(atm.id, 0) > 0) or atm.under_attack or (atm.status == AtmStatus.LOCKDOWN)
        
        # Determine live marker category
        marker_color = "#10b981"  # GREEN: Online
        if atm.status == AtmStatus.LOCKDOWN or has_critical:
            marker_color = "#ef4444"  # RED: Lockdown / Critical
        elif atm.status == AtmStatus.OFFLINE:
            marker_color = "#64748b"  # GRAY: Offline
        elif atm.status == AtmStatus.MAINTENANCE or atm.network_status.value == "DEGRADED":
            marker_color = "#f59e0b"  # YELLOW: Warning
        elif getattr(atm, "risk_score", 5) > 60:
            marker_color = "#f97316"  # ORANGE: High Risk

        map_nodes.append({
            "id": atm.id,
            "atm_code": atm.atm_code,
            "city": atm.city,
            "address": atm.address,
            "latitude": float(atm.latitude),
            "longitude": float(atm.longitude),
            "status": atm.status.value,
            "network_status": atm.network_status.value,
            "cash_total": float(atm.cash_total),
            "security_status": atm.security_status,
            "risk_score": getattr(atm, "risk_score", 5),
            "firmware_version": getattr(atm, "firmware_version", "SV-ATM-FW-3.4.1"),
            "firmware_hash": getattr(atm, "firmware_hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            "secure_boot_enabled": getattr(atm, "secure_boot_enabled", True),
            "certificate_id": getattr(atm, "certificate_id", f"CERT-{atm.atm_code}"),
            "certificate_status": getattr(atm, "certificate_status", "VALID"),
            "latency_ms": getattr(atm, "latency_ms", 24),
            "cpu_usage": getattr(atm, "cpu_usage", 18),
            "memory_usage": getattr(atm, "memory_usage", 32),
            "disk_usage": getattr(atm, "disk_usage", 45),
            "under_attack": bool(getattr(atm, "under_attack", False) or has_critical),
            "marker_color": marker_color,
            "active_alerts_count": active_alerts_map.get(atm.id, 0),
            "open_incidents_count": open_incidents_map.get(atm.id, 0),
            "sensors": sensor_dict,
            "last_heartbeat": atm.last_heartbeat.isoformat()
        })
    return map_nodes


@router.get("/analytics")
async def get_soc_analytics(
    current_user: User = Depends(require_permission("soc:dashboard")),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """Generates statistical analytics datasets for Recharts visualization using pandas."""
    # 1. Fetch recent transactions
    stmt_tx = select(Transaction).order_by(Transaction.created_at.desc()).limit(500)
    res_tx = await db.execute(stmt_tx)
    txns = res_tx.scalars().all()

    tx_by_hour = []
    risk_distribution = {"0-20": 0, "21-40": 0, "41-60": 0, "61-80": 0, "81-100": 0}

    if txns:
        tx_data = [{"hour": t.created_at.hour, "amount": float(t.amount), "risk": t.risk_score} for t in txns]
        df_tx = pd.DataFrame(tx_data)
        
        # Hourly volume
        hourly = df_tx.groupby("hour").agg(count=("amount", "count"), total=("amount", "sum")).reset_index()
        for _, row in hourly.iterrows():
            tx_by_hour.append({
                "hour": f"{int(row['hour']):02d}:00",
                "count": int(row["count"]),
                "volume": float(row["total"])
            })

        # Risk score bins
        for score in df_tx["risk"]:
            if score <= 20:
                risk_distribution["0-20"] += 1
            elif score <= 40:
                risk_distribution["21-40"] += 1
            elif score <= 60:
                risk_distribution["41-60"] += 1
            elif score <= 80:
                risk_distribution["61-80"] += 1
            else:
                risk_distribution["81-100"] += 1

    # 2. Threat Severity distribution from SecurityEvents
    stmt_ev = select(SecurityEvent.severity, func.count(SecurityEvent.id)).group_by(SecurityEvent.severity)
    res_ev = await db.execute(stmt_ev)
    severity_dist = {sev.value: count for sev, count in res_ev.all()}

    # 3. Incident Threat Types
    stmt_inc = select(Incident.threat_type, func.count(Incident.id)).group_by(Incident.threat_type)
    res_inc = await db.execute(stmt_inc)
    threat_types = {tt: count for tt, count in res_inc.all()}

    return {
        "transactions_hourly": sorted(tx_by_hour, key=lambda x: x["hour"]),
        "risk_distribution": [{"bracket": k, "count": v} for k, v in risk_distribution.items()],
        "threat_severity": [{"severity": k, "count": v} for k, v in severity_dist.items()],
        "incident_types": [{"type": k, "count": v} for k, v in threat_types.items()],
    }


import io
import csv
import json
from fastapi.responses import Response
from sqlalchemy import or_, and_
from app.audit.writer import write_audit_log

@router.get("/events")
async def get_security_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    severity: Optional[SeverityLevel] = None,
    event_type: Optional[str] = None,
    atm_id: Optional[int] = None,
    user_id: Optional[int] = None,
    search: Optional[str] = None,
    mitre_tactic: Optional[str] = None,
    is_simulated: Optional[bool] = None,
    rule_id: Optional[str] = None,
    current_user: User = Depends(require_permission("soc:dashboard")),
    db: AsyncSession = Depends(get_db)
):
    """SIEM Event Explorer: server-side pagination, full-text search, and multi-dimensional filters."""
    stmt = select(SecurityEvent).order_by(SecurityEvent.created_at.desc())
    count_stmt = select(func.count(SecurityEvent.id))

    filters = []
    if severity:
        filters.append(SecurityEvent.severity == severity)
    if event_type:
        filters.append(SecurityEvent.type == event_type)
    if atm_id:
        filters.append(SecurityEvent.atm_id == atm_id)
    if user_id:
        filters.append(SecurityEvent.user_id == user_id)
    if mitre_tactic:
        filters.append(SecurityEvent.mitre_tactic == mitre_tactic)
    if is_simulated is not None:
        filters.append(SecurityEvent.is_simulated == is_simulated)
    if rule_id:
        filters.append(SecurityEvent.rule_id == rule_id)
    if search:
        search_filter = or_(
            SecurityEvent.type.ilike(f"%{search}%"),
            SecurityEvent.source.ilike(f"%{search}%"),
            SecurityEvent.ip_address.ilike(f"%{search}%"),
            SecurityEvent.correlation_key.ilike(f"%{search}%"),
            SecurityEvent.mitre_technique.ilike(f"%{search}%")
        )
        filters.append(search_filter)

    if filters:
        stmt = stmt.where(and_(*filters))
        count_stmt = count_stmt.where(and_(*filters))

    # Total count
    total_res = await db.execute(count_stmt)
    total_count = total_res.scalar() or 0

    # Paginate
    offset = (page - 1) * page_size
    stmt = stmt.offset(offset).limit(page_size)
    res = await db.execute(stmt)
    events = res.scalars().all()

    formatted_events = []
    for ev in events:
        details = ev.details or {}
        trace = details.get("pipeline_trace", [])
        risk_score = details.get("risk_score", 0)
        fired_rule = details.get("fired_rule") or ev.rule_id

        formatted_events.append({
            "id": ev.id,
            "event_id": f"EVT-{ev.id:06d}",
            "type": ev.type,
            "severity": ev.severity.value,
            "source": ev.source,
            "atm_id": ev.atm_id,
            "user_id": ev.user_id,
            "account_id": ev.account_id,
            "ip_address": ev.ip_address,
            "correlation_key": ev.correlation_key,
            "mitre_technique": ev.mitre_technique,
            "mitre_tactic": ev.mitre_tactic,
            "incident_id": ev.incident_id,
            "rule_id": ev.rule_id,
            "fired_rule": fired_rule,
            "risk_score": risk_score,
            "is_simulated": ev.is_simulated,
            "trace_step_count": len(trace),
            "created_at": ev.created_at.isoformat() if ev.created_at else None
        })

    return {
        "total": total_count,
        "page": page,
        "page_size": page_size,
        "total_pages": (total_count + page_size - 1) // page_size if total_count > 0 else 1,
        "events": formatted_events
    }


@router.get("/events/{event_id}")
async def get_security_event_detail(
    event_id: int,
    current_user: User = Depends(require_permission("soc:dashboard")),
    db: AsyncSession = Depends(get_db)
):
    """Fetches full normalized event, pipeline trace, linked alerts and linked incident."""
    stmt = select(SecurityEvent).options(selectinload(SecurityEvent.alerts)).where(SecurityEvent.id == event_id)
    res = await db.execute(stmt)
    ev = res.scalar_one_or_none()
    if not ev:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Security event not found.")

    incident_data = None
    if ev.incident_id:
        stmt_inc = select(Incident).where(Incident.id == ev.incident_id)
        res_inc = await db.execute(stmt_inc)
        inc = res_inc.scalar_one_or_none()
        if inc:
            incident_data = {
                "id": inc.id,
                "incident_code": inc.incident_code,
                "severity": inc.severity.value,
                "threat_type": inc.threat_type,
                "status": inc.status.value,
                "summary": inc.summary
            }

    details = ev.details or {}
    trace = details.get("pipeline_trace", [])

    return {
        "id": ev.id,
        "event_id": f"EVT-{ev.id:06d}",
        "type": ev.type,
        "severity": ev.severity.value,
        "source": ev.source,
        "atm_id": ev.atm_id,
        "user_id": ev.user_id,
        "account_id": ev.account_id,
        "ip_address": ev.ip_address,
        "device_id": ev.device_id,
        "correlation_key": ev.correlation_key,
        "mitre_technique": ev.mitre_technique,
        "mitre_tactic": ev.mitre_tactic,
        "incident": incident_data,
        "rule_id": ev.rule_id,
        "is_simulated": ev.is_simulated,
        "created_at": ev.created_at.isoformat() if ev.created_at else None,
        "details": details,
        "pipeline_trace": trace,
        "alerts": [
            {
                "id": a.id,
                "title": a.title,
                "message": a.message,
                "severity": a.severity.value,
                "status": a.status.value,
                "created_at": a.created_at.isoformat() if a.created_at else None
            }
            for a in ev.alerts
        ]
    }


@router.get("/events-export")
async def export_security_events(
    format: str = Query("json", regex="^(json|csv)$"),
    severity: Optional[SeverityLevel] = None,
    is_simulated: Optional[bool] = None,
    current_user: User = Depends(require_permission("soc:dashboard")),
    db: AsyncSession = Depends(get_db)
):
    """Exports SIEM events as CSV or JSON and logs to logs/siem_export.jsonl."""
    stmt = select(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(1000)
    if severity:
        stmt = stmt.where(SecurityEvent.severity == severity)
    if is_simulated is not None:
        stmt = stmt.where(SecurityEvent.is_simulated == is_simulated)

    res = await db.execute(stmt)
    events = res.scalars().all()

    # Append to logs/siem_export.jsonl
    try:
        with open("logs/siem_export.jsonl", "a", encoding="utf-8") as f:
            for ev in events:
                entry = {
                    "event_id": ev.id,
                    "timestamp": ev.created_at.isoformat() if ev.created_at else None,
                    "type": ev.type,
                    "severity": ev.severity.value,
                    "source": ev.source,
                    "atm_id": ev.atm_id,
                    "ip": ev.ip_address,
                    "rule_id": ev.rule_id,
                    "mitre": ev.mitre_technique,
                    "is_simulated": ev.is_simulated
                }
                f.write(json.dumps(entry) + "\n")
    except Exception as io_err:
        pass

    # Audit export
    await write_audit_log(
        db=db,
        action="SIEM_EVENTS_EXPORTED",
        resource_type="SECURITY_EVENT",
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        payload={"format": format, "count": len(events)}
    )
    await db.commit()

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Timestamp", "Type", "Severity", "Source", "ATM_ID", "IP", "Rule_ID", "MITRE", "Simulated"])
        for ev in events:
            writer.writerow([
                ev.id,
                ev.created_at.isoformat() if ev.created_at else "",
                ev.type,
                ev.severity.value,
                ev.source,
                ev.atm_id or "",
                ev.ip_address or "",
                ev.rule_id or "",
                ev.mitre_technique or "",
                ev.is_simulated
            ])
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=siem_events.csv"}
        )
    else:
        export_data = [
            {
                "id": ev.id,
                "timestamp": ev.created_at.isoformat() if ev.created_at else None,
                "type": ev.type,
                "severity": ev.severity.value,
                "source": ev.source,
                "atm_id": ev.atm_id,
                "ip": ev.ip_address,
                "rule_id": ev.rule_id,
                "mitre_technique": ev.mitre_technique,
                "mitre_tactic": ev.mitre_tactic,
                "is_simulated": ev.is_simulated,
                "details": ev.details
            }
            for ev in events
        ]
        return export_data

