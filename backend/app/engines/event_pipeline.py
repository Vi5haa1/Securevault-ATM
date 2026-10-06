import time
import uuid
import datetime
import logging
from typing import Dict, Any, Optional, List, Tuple
from decimal import Decimal
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func, update

from app.db.models.models import (
    SecurityEvent, Alert, Incident, IncidentAction, IncidentStatus,
    SeverityLevel, AlertStatus, Atm, AtmStatus, Card, CardStatus,
    Account, AccountStatus, UserSession, DetectionRule, ThreatIndicator
)
from app.audit.writer import write_audit_log
from app.api.v1.ws import broadcast_soc_event

logger = logging.getLogger("securevault.pipeline")


class RawEvent:
    def __init__(
        self,
        event_type: str,
        source: str,
        severity_hint: SeverityLevel = SeverityLevel.LOW,
        atm_id: Optional[int] = None,
        user_id: Optional[int] = None,
        account_id: Optional[int] = None,
        card_id: Optional[int] = None,
        ip_address: Optional[str] = None,
        device_id: Optional[str] = None,
        session_id: Optional[str] = None,
        correlation_key: Optional[str] = None,
        raw_payload: Optional[Dict[str, Any]] = None,
        is_simulated: bool = False,
        mitre_technique: Optional[str] = None,
        mitre_tactic: Optional[str] = None
    ):
        self.event_type = event_type
        self.source = source
        self.severity_hint = severity_hint
        self.atm_id = atm_id
        self.user_id = user_id
        self.account_id = account_id
        self.card_id = card_id
        self.ip_address = ip_address
        self.device_id = device_id
        self.session_id = session_id
        self.correlation_key = correlation_key or f"{event_type}:{atm_id or user_id or ip_address or 'global'}"
        self.raw_payload = raw_payload or {}
        self.is_simulated = is_simulated
        self.mitre_technique = mitre_technique
        self.mitre_tactic = mitre_tactic


class EventPipeline:
    """
    Central Defensive Security Event Pipeline (The Backbone)
    COLLECT -> NORMALIZE -> CORRELATE -> RISK SCORE -> DETECTION RULE -> ALERT -> INCIDENT -> PLAYBOOK -> RESPONSE -> AUDIT
    All event producers (ATM Kiosk, API Gateway, Auth, Hardware Sensors, Simulations) pass through this unified pipeline.
    """

    @classmethod
    async def process_event(cls, db: AsyncSession, raw: RawEvent) -> Dict[str, Any]:
        trace: List[Dict[str, Any]] = []
        overall_start = time.time()

        # -------------------------------------------------------------
        # 1. COLLECT STAGE
        # -------------------------------------------------------------
        t0 = time.time()
        event_uuid = f"EVT-{uuid.uuid4().hex[:12].upper()}"
        timestamp_now = datetime.datetime.now(datetime.timezone.utc)
        trace.append({
            "stage": "COLLECT",
            "status": "COMPLETED",
            "result": f"Ingested raw event '{raw.event_type}' from '{raw.source}'",
            "duration_ms": round((time.time() - t0) * 1000, 2),
            "timestamp": timestamp_now.isoformat()
        })

        # -------------------------------------------------------------
        # 2. NORMALIZE STAGE
        # -------------------------------------------------------------
        t0 = time.time()
        # Technique / tactic defaults if not provided
        mitre_map = {
            "FAILED_PIN": ("T1110 - Brute Force", "Credential Access"),
            "ATM_TAMPER": ("T1200 - Hardware Additions", "Initial Access"),
            "API_RATE_LIMIT": ("T1499 - Endpoint Denial of Service", "Impact"),
            "TOKEN_REPLAY": ("T1550 - Use Alternate Authentication Material", "Defense Evasion"),
            "PRIVILEGE_ESCALATION": ("T1078 - Valid Accounts", "Privilege Escalation"),
            "FIRMWARE_TAMPER": ("T1542 - Pre-OS Boot", "Persistence"),
            "CERT_FAILURE": ("T1556 - Modify Authentication Process", "Defense Evasion"),
            "SUSPICIOUS_TXN": ("T1078 - Valid Accounts", "Initial Access"),
            "IMPOSSIBLE_TRAVEL": ("T1078.004 - Cloud Accounts", "Initial Access"),
            "MALICIOUS_IP": ("T1071 - Application Layer Protocol", "Command and Control")
        }
        technique, tactic = mitre_map.get(raw.event_type, (raw.mitre_technique or "T1078 - Security Event", raw.mitre_tactic or "Defense"))

        normalized = {
            "event_id": event_uuid,
            "timestamp": timestamp_now,
            "type": raw.event_type,
            "source": raw.source,
            "severity": raw.severity_hint,
            "atm_id": raw.atm_id,
            "user_id": raw.user_id,
            "account_id": raw.account_id,
            "ip_address": raw.ip_address,
            "device_id": raw.device_id,
            "session_id": raw.session_id,
            "correlation_key": raw.correlation_key,
            "is_simulated": raw.is_simulated,
            "mitre_technique": technique,
            "mitre_tactic": tactic,
            "payload": raw.raw_payload
        }
        trace.append({
            "stage": "NORMALIZE",
            "status": "COMPLETED",
            "result": f"Normalized schema applied. MITRE: {technique} [{tactic}]",
            "duration_ms": round((time.time() - t0) * 1000, 2),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        })

        # -------------------------------------------------------------
        # 3. CORRELATE STAGE
        # -------------------------------------------------------------
        t0 = time.time()
        window_minutes = 5
        cutoff = timestamp_now - datetime.timedelta(minutes=window_minutes)

        # Count previous matching events in correlation window
        stmt_corr = select(func.count(SecurityEvent.id)).where(
            and_(
                SecurityEvent.correlation_key == raw.correlation_key,
                SecurityEvent.type == raw.event_type,
                SecurityEvent.created_at >= cutoff
            )
        )
        res_corr = await db.execute(stmt_corr)
        recent_count = (res_corr.scalar() or 0) + 1  # Including current event

        trace.append({
            "stage": "CORRELATE",
            "status": "COMPLETED",
            "result": f"Grouped by key '{raw.correlation_key}'. Cluster count in last {window_minutes}m: {recent_count}",
            "duration_ms": round((time.time() - t0) * 1000, 2),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        })

        # -------------------------------------------------------------
        # 4. RISK SCORE STAGE
        # -------------------------------------------------------------
        t0 = time.time()
        # Compute dynamic risk score
        risk_score = 10
        risk_factors: Dict[str, Any] = {}

        if raw.event_type == "FAILED_PIN":
            risk_score = min(100, 20 * recent_count)
            risk_factors["consecutive_pin_failures"] = recent_count
        elif raw.event_type == "ATM_TAMPER":
            risk_score = 98
            risk_factors["physical_cabinet_sensor_breached"] = True
        elif raw.event_type == "FIRMWARE_TAMPER":
            risk_score = 95
            risk_factors["cryptographic_hash_mismatch"] = True
        elif raw.event_type == "CERT_FAILURE":
            risk_score = 90
            risk_factors["mTLS_certificate_revoked_or_expired"] = True
        elif raw.event_type == "API_RATE_LIMIT":
            risk_score = 75
            risk_factors["request_threshold_exceeded"] = True
        elif raw.event_type == "TOKEN_REPLAY":
            risk_score = 88
            risk_factors["refresh_token_family_reuse"] = True
        elif raw.event_type == "PRIVILEGE_ESCALATION":
            risk_score = 92
            risk_factors["unauthorized_role_elevation"] = True
        else:
            base_risk = 25 if raw.severity_hint == SeverityLevel.MEDIUM else (70 if raw.severity_hint == SeverityLevel.HIGH else 10)
            risk_score = base_risk

        # Check threat intel
        if raw.ip_address:
            stmt_ti = select(ThreatIndicator).where(
                and_(ThreatIndicator.value == raw.ip_address, ThreatIndicator.is_active == True)
            )
            res_ti = await db.execute(stmt_ti)
            ti_match = res_ti.scalar_one_or_none()
            if ti_match:
                risk_score = min(100, risk_score + 35)
                risk_factors["threat_intel_hit"] = {
                    "category": ti_match.threat_category,
                    "confidence": ti_match.confidence
                }

        # Determine adjusted severity
        effective_severity = raw.severity_hint
        if risk_score >= 80:
            effective_severity = SeverityLevel.CRITICAL
        elif risk_score >= 60:
            effective_severity = SeverityLevel.HIGH
        elif risk_score >= 35:
            effective_severity = SeverityLevel.MEDIUM

        trace.append({
            "stage": "RISK_SCORE",
            "status": "COMPLETED",
            "result": f"Risk score: {risk_score}/100. Severity: {effective_severity.value}. Factors: {list(risk_factors.keys())}",
            "duration_ms": round((time.time() - t0) * 1000, 2),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        })

        # -------------------------------------------------------------
        # 5. DETECTION RULE MATCH STAGE
        # -------------------------------------------------------------
        t0 = time.time()
        fired_rule_id: Optional[str] = None
        fired_rule_name: Optional[str] = None
        rule_actions: List[str] = []

        # Query DB detection rules
        stmt_rules = select(DetectionRule).where(DetectionRule.enabled == True)
        res_rules = await db.execute(stmt_rules)
        active_rules = res_rules.scalars().all()

        for rule in active_rules:
            if raw.event_type in rule.event_types:
                # Check condition threshold
                cond = rule.conditions
                threshold = cond.get("threshold", 1)
                field = cond.get("field", "count")

                match = False
                if field == "count" and recent_count >= threshold:
                    match = True
                elif field == "sensor_state" and cond.get("value") == "ALERT":
                    match = True
                elif field == "risk_score" and risk_score >= threshold:
                    match = True
                elif field == "immediate":
                    match = True

                if match:
                    fired_rule_id = rule.rule_id
                    fired_rule_name = rule.name
                    rule_actions = rule.actions
                    rule.hit_count += 1
                    rule.last_hit_at = timestamp_now
                    break

        # Fallback default rule if none explicitly in DB yet
        if not fired_rule_id:
            if raw.event_type == "FAILED_PIN" and recent_count >= 5:
                fired_rule_id = "RULE-SV-001"
                fired_rule_name = "Multiple Failed PIN Attempts (Brute Force)"
                rule_actions = ["LOCK_ACCOUNT", "LOCK_CARD", "CREATE_ALERT", "CREATE_INCIDENT", "NOTIFY_SOC"]
            elif raw.event_type == "ATM_TAMPER":
                fired_rule_id = "RULE-SV-003"
                fired_rule_name = "Physical ATM Cabinet Breach"
                rule_actions = ["LOCKDOWN_ATM", "TERMINATE_SESSIONS", "CREATE_ALERT", "CREATE_INCIDENT", "NOTIFY_SOC"]
            elif raw.event_type in ["FIRMWARE_TAMPER", "CERT_FAILURE", "TOKEN_REPLAY", "PRIVILEGE_ESCALATION"]:
                fired_rule_id = f"RULE-SV-{raw.event_type[:6]}"
                fired_rule_name = f"Automated Security Violation: {raw.event_type}"
                rule_actions = ["CREATE_ALERT", "CREATE_INCIDENT", "NOTIFY_SOC"]

        trace.append({
            "stage": "DETECTION_RULE",
            "status": "COMPLETED",
            "result": f"Matched Rule: {fired_rule_id or 'NONE'} ('{fired_rule_name or 'No rule matched'}')",
            "duration_ms": round((time.time() - t0) * 1000, 2),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        })

        # -------------------------------------------------------------
        # 6. ALERT STAGE
        # -------------------------------------------------------------
        t0 = time.time()
        created_alert: Optional[Alert] = None
        if fired_rule_id or effective_severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
            alert_title = f"{fired_rule_name or raw.event_type}: [{raw.correlation_key}]"
            alert_msg = f"Security trigger fired for {raw.event_type} at {raw.source}. Risk Score: {risk_score}."
            
            created_alert = Alert(
                severity=effective_severity,
                title=alert_title,
                message=alert_msg,
                status=AlertStatus.NEW
            )
            # Will be attached to SecurityEvent
            trace.append({
                "stage": "ALERT",
                "status": "COMPLETED",
                "result": f"Alert generated: '{alert_title}' ({effective_severity.value})",
                "duration_ms": round((time.time() - t0) * 1000, 2),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            })
        else:
            trace.append({
                "stage": "ALERT",
                "status": "SKIPPED",
                "result": "Event below alert threshold.",
                "duration_ms": round((time.time() - t0) * 1000, 2),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            })

        # -------------------------------------------------------------
        # 7. INCIDENT STAGE (CORRELATED DEDUPLICATION)
        # -------------------------------------------------------------
        t0 = time.time()
        incident_obj: Optional[Incident] = None

        if "CREATE_INCIDENT" in rule_actions or effective_severity == SeverityLevel.CRITICAL:
            # Check for existing OPEN/INVESTIGATING incident on this correlation key within window
            stmt_inc = select(Incident).where(
                and_(
                    Incident.threat_type == raw.event_type,
                    Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING])
                )
            )
            if raw.atm_id:
                stmt_inc = stmt_inc.where(Incident.atm_id == raw.atm_id)
            if raw.account_id:
                stmt_inc = stmt_inc.where(Incident.account_id == raw.account_id)

            res_inc = await db.execute(stmt_inc)
            incident_obj = res_inc.scalars().first()

            if incident_obj:
                # Correlated into existing incident!
                trace.append({
                    "stage": "INCIDENT",
                    "status": "CORRELATED",
                    "result": f"Correlated into existing active Incident {incident_obj.incident_code} (prevented alert flood).",
                    "duration_ms": round((time.time() - t0) * 1000, 2),
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
                })
            else:
                # Create brand new incident
                inc_code = f"SV-INC-{datetime.datetime.now().year}-{uuid.uuid4().hex[:5].upper()}"
                incident_obj = Incident(
                    incident_code=inc_code,
                    severity=effective_severity,
                    threat_type=raw.event_type,
                    atm_id=raw.atm_id,
                    account_id=raw.account_id,
                    status=IncidentStatus.OPEN,
                    summary=f"Automated Incident: {fired_rule_name or raw.event_type} detected. Triggered by {raw.source}.",
                    is_simulated=raw.is_simulated
                )
                db.add(incident_obj)
                await db.flush()  # assign incident_obj.id

                trace.append({
                    "stage": "INCIDENT",
                    "status": "CREATED",
                    "result": f"Spawned new Incident: {inc_code} ({effective_severity.value})",
                    "duration_ms": round((time.time() - t0) * 1000, 2),
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
                })

        # -------------------------------------------------------------
        # 8 & 9. PLAYBOOK & RESPONSE STAGE
        # -------------------------------------------------------------
        t0 = time.time()
        executed_responses: List[str] = []

        if "LOCK_CARD" in rule_actions and raw.card_id:
            await db.execute(update(Card).where(Card.id == raw.card_id).values(status=CardStatus.LOCKED))
            executed_responses.append("Card locked in banking database")

        if "LOCK_ACCOUNT" in rule_actions and raw.account_id:
            await db.execute(update(Account).where(Account.id == raw.account_id).values(status=AccountStatus.LOCKED))
            executed_responses.append("Account placed on security hold")

        if "LOCKDOWN_ATM" in rule_actions and raw.atm_id:
            await db.execute(update(Atm).where(Atm.id == raw.atm_id).values(status=AtmStatus.LOCKDOWN, security_status="BREACHED", under_attack=True))
            executed_responses.append("ATM placed in emergency LOCKDOWN")

        if "TERMINATE_SESSIONS" in rule_actions and raw.atm_id:
            await db.execute(
                update(UserSession)
                .where(and_(UserSession.atm_id == raw.atm_id, UserSession.terminated_at.is_(None)))
                .values(terminated_at=timestamp_now, termination_reason="SECURITY_CONTAINMENT_LOCKDOWN")
            )
            executed_responses.append("Active kiosk sessions terminated")

        if incident_obj and ("CREATE_INCIDENT" in rule_actions or "NOTIFY_SOC" in rule_actions):
            executed_responses.append("SOC incident alert dispatched to SIEM console")

        if incident_obj and executed_responses:
            for resp in executed_responses:
                action_rec = IncidentAction(
                    incident_id=incident_obj.id,
                    action_type="CONTAINMENT",
                    result=resp
                )
                db.add(action_rec)

        trace.append({
            "stage": "PLAYBOOK",
            "status": "EXECUTED",
            "result": f"Executed actions: {', '.join(executed_responses) if executed_responses else 'None required'}",
            "duration_ms": round((time.time() - t0) * 1000, 2),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        })

        # -------------------------------------------------------------
        # 10. PERSIST SECURITY EVENT WITH TRACE
        # -------------------------------------------------------------
        sec_event = SecurityEvent(
            type=raw.event_type,
            severity=effective_severity,
            source=raw.source,
            atm_id=raw.atm_id,
            user_id=raw.user_id,
            account_id=raw.account_id,
            ip_address=raw.ip_address,
            correlation_key=raw.correlation_key,
            mitre_technique=technique,
            mitre_tactic=tactic,
            incident_id=incident_obj.id if incident_obj else None,
            rule_id=fired_rule_id,
            device_id=raw.device_id,
            is_simulated=raw.is_simulated,
            details={
                **raw.raw_payload,
                "risk_score": risk_score,
                "risk_factors": risk_factors,
                "fired_rule": fired_rule_name,
                "pipeline_trace": trace,
                "executed_responses": executed_responses
            }
        )
        db.add(sec_event)
        await db.flush()

        if created_alert:
            created_alert.event_id = sec_event.id
            db.add(created_alert)

        # -------------------------------------------------------------
        # 11. AUDIT STAGE
        # -------------------------------------------------------------
        t0 = time.time()
        audit_entry = await write_audit_log(
            db=db,
            action=f"PIPELINE_{raw.event_type}",
            resource_type="SECURITY_EVENT",
            resource_id=str(sec_event.id),
            actor_id=str(raw.user_id or "PIPELINE_ENGINE"),
            actor_role="SECURITY_SYSTEM",
            payload={
                "event_id": event_uuid,
                "type": raw.event_type,
                "severity": effective_severity.value,
                "rule_id": fired_rule_id,
                "incident_code": incident_obj.incident_code if incident_obj else None,
                "responses": executed_responses,
                "is_simulated": raw.is_simulated
            },
            ip_address=raw.ip_address
        )

        trace.append({
            "stage": "AUDIT",
            "status": "COMPLETED",
            "result": f"Appended to SHA-256 hash chain (Seq #{audit_entry.sequence_no})",
            "duration_ms": round((time.time() - t0) * 1000, 2),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        })

        total_duration = round((time.time() - overall_start) * 1000, 2)

        # -------------------------------------------------------------
        # 12. REAL-TIME BROADCAST
        # -------------------------------------------------------------
        try:
            await broadcast_soc_event({
                "type": "SECURITY_EVENT",
                "event": {
                    "id": sec_event.id,
                    "event_type": raw.event_type,
                    "severity": effective_severity.value,
                    "atm_id": raw.atm_id,
                    "risk_score": risk_score,
                    "rule": fired_rule_name,
                    "incident_code": incident_obj.incident_code if incident_obj else None,
                    "is_simulated": raw.is_simulated,
                    "timestamp": timestamp_now.isoformat()
                }
            })
        except Exception as ws_err:
            logger.warning(f"WebSocket broadcast skipped: {ws_err}")

        return {
            "event_id": event_uuid,
            "security_event_id": sec_event.id,
            "severity": effective_severity.value,
            "risk_score": risk_score,
            "fired_rule_id": fired_rule_id,
            "fired_rule_name": fired_rule_name,
            "incident_code": incident_obj.incident_code if incident_obj else None,
            "actions_executed": executed_responses,
            "total_duration_ms": total_duration,
            "pipeline_trace": trace
        }
