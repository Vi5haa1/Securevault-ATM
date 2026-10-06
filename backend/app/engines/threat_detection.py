import datetime
from typing import Optional, Dict, Any, Tuple
from decimal import Decimal
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.db.models.models import (
    SecurityEvent, Alert, Incident, IncidentStatus, AlertStatus,
    SeverityLevel, Card, CardStatus, Account, AccountStatus,
    Atm, AtmStatus, User
)
from app.engines.playbooks import AutomatedPlaybookEngine
from app.engines.notifier import hub


def generate_incident_code() -> str:
    """Generates unique incident code in format SV-INC-YYYY-NNNNN."""
    now = datetime.datetime.now(datetime.timezone.utc)
    import secrets
    num = secrets.randbelow(90000) + 10000
    return f"SV-INC-{now.year}-{num}"


class ThreatDetectionEngine:
    """
    Central Threat Detection Engine.
    Detects security anomalies, emits SecurityEvents, triggers Alerts,
    and escalates to Incidents with automated containment playbooks.
    """

    @classmethod
    async def handle_failed_pin(
        cls,
        db: AsyncSession,
        card: Card,
        atm: Atm,
        ip_address: Optional[str] = None,
        is_simulated: bool = False
    ) -> Tuple[bool, Optional[Incident]]:
        """
        Handles failed PIN attempts. Increments counter.
        At 5 failed attempts, initiates Brute Force Lockout and Incident.
        """
        card.pin_failed_attempts += 1
        account_id = card.account_id

        # Fetch account for customer user_id
        stmt_acc = select(Account).where(Account.id == account_id)
        res_acc = await db.execute(stmt_acc)
        account = res_acc.scalar_one_or_none()
        customer_id = account.customer_id if account else None

        # 1. Create SecurityEvent
        severity = SeverityLevel.MEDIUM if card.pin_failed_attempts < 5 else SeverityLevel.HIGH
        event = SecurityEvent(
            type="FAILED_PIN_ATTEMPT",
            severity=severity,
            source=f"ATM:{atm.atm_code}",
            atm_id=atm.id,
            account_id=account_id,
            ip_address=ip_address,
            details={
                "card_last4": card.last4,
                "attempt_count": card.pin_failed_attempts,
                "threshold": 5,
                "atm_code": atm.atm_code
            },
            is_simulated=is_simulated
        )
        db.add(event)
        await db.flush()

        incident: Optional[Incident] = None

        # 2. Check if Brute Force threshold reached
        if card.pin_failed_attempts >= 5:
            # Escalated to Incident
            inc_code = generate_incident_code()
            incident = Incident(
                incident_code=inc_code,
                severity=SeverityLevel.HIGH,
                threat_type="BRUTE_FORCE",
                atm_id=atm.id,
                account_id=account_id,
                status=IncidentStatus.OPEN,
                summary=f"Automated Brute Force detected on card ending in {card.last4} at terminal {atm.atm_code}. 5 consecutive failed PIN attempts.",
                is_simulated=is_simulated
            )
            db.add(incident)
            await db.flush()

            # Create Alert
            alert = Alert(
                event_id=event.id,
                severity=SeverityLevel.HIGH,
                title=f"Brute Force Detected: Card {card.last4}",
                message=f"5 consecutive failed PIN entries detected at ATM {atm.atm_code}. Protective lockout triggered.",
                status=AlertStatus.NEW
            )
            db.add(alert)
            await db.flush()

            # Execute automated playbook
            await AutomatedPlaybookEngine.execute_brute_force_containment(
                db=db,
                incident=incident,
                card_id=card.id,
                account_id=account_id,
                atm_id=atm.id
            )

            # Broadcast WebSocket alert
            await hub.emit_security_alert(
                alert_id=alert.id,
                title=alert.title,
                message=alert.message,
                severity="HIGH",
                threat_type="BRUTE_FORCE",
                atm_id=atm.id,
                account_id=account_id
            )

            return True, incident

        await db.flush()
        return False, None

    @classmethod
    async def handle_tamper_event(
        cls,
        db: AsyncSession,
        atm: Atm,
        sensor_type: str,
        details: Optional[Dict[str, Any]] = None,
        is_simulated: bool = False
    ) -> Incident:
        """
        Handles physical/hardware tamper triggers.
        Puts ATM in lockdown and creates CRITICAL Incident with full playbook containment.
        """
        # 1. Security Event
        event = SecurityEvent(
            type="ATM_PHYSICAL_TAMPER",
            severity=SeverityLevel.CRITICAL,
            source=f"ATM_SENSOR:{sensor_type}",
            atm_id=atm.id,
            details=details or {"sensor": sensor_type, "state": "ALERT"},
            is_simulated=is_simulated
        )
        db.add(event)
        await db.flush()

        # 2. Alert
        alert = Alert(
            event_id=event.id,
            severity=SeverityLevel.CRITICAL,
            title=f"CRITICAL: ATM Tamper Alarm ({atm.atm_code})",
            message=f"Tamper trigger on {sensor_type} sensor at {atm.atm_code}, {atm.city}. Terminal placed in lockdown.",
            status=AlertStatus.NEW
        )
        db.add(alert)
        await db.flush()

        # 3. Incident
        inc_code = generate_incident_code()
        incident = Incident(
            incident_code=inc_code,
            severity=SeverityLevel.CRITICAL,
            threat_type="ATM_TAMPER",
            atm_id=atm.id,
            status=IncidentStatus.OPEN,
            summary=f"Hardware tamper alarm triggered by {sensor_type} at {atm.atm_code} ({atm.city}, {atm.address}). Protective emergency shutdown executed.",
            is_simulated=is_simulated
        )
        db.add(incident)
        await db.flush()

        # 4. Containment Playbook
        await AutomatedPlaybookEngine.execute_tamper_containment(
            db=db,
            incident=incident,
            atm_id=atm.id
        )

        # 5. Broadcast to SOC
        await hub.emit_security_alert(
            alert_id=alert.id,
            title=alert.title,
            message=alert.message,
            severity="CRITICAL",
            threat_type="ATM_TAMPER",
            atm_id=atm.id
        )

        return incident

    @classmethod
    async def handle_suspicious_transaction(
        cls,
        db: AsyncSession,
        atm: Atm,
        account_id: int,
        amount: Decimal,
        risk_score: int,
        risk_level: str,
        risk_factors: Dict[str, Any],
        is_simulated: bool = False
    ) -> Optional[Incident]:
        """
        Handles high/critical risk transactions detected by the Risk Engine.
        """
        event = SecurityEvent(
            type="SUSPICIOUS_TRANSACTION_DETECTED",
            severity=SeverityLevel.HIGH if risk_level == "HIGH" else SeverityLevel.CRITICAL,
            source="RISK_ENGINE",
            atm_id=atm.id,
            account_id=account_id,
            details={
                "amount": str(amount),
                "risk_score": risk_score,
                "risk_level": risk_level,
                "factors": risk_factors
            },
            is_simulated=is_simulated
        )
        db.add(event)
        await db.flush()

        alert = Alert(
            event_id=event.id,
            severity=SeverityLevel.HIGH if risk_level == "HIGH" else SeverityLevel.CRITICAL,
            title=f"Suspicious Transaction (Risk Score {risk_score})",
            message=f"High risk financial transaction of INR {amount:,.2f} flagged at ATM {atm.atm_code}.",
            status=AlertStatus.NEW
        )
        db.add(alert)
        await db.flush()

        incident = None
        if risk_score >= 80:
            # Escalate critical to Incident
            inc_code = generate_incident_code()
            incident = Incident(
                incident_code=inc_code,
                severity=SeverityLevel.CRITICAL,
                threat_type="SUSPICIOUS_TRANSACTION",
                atm_id=atm.id,
                account_id=account_id,
                status=IncidentStatus.OPEN,
                summary=f"Automated block of high-anomaly transaction of INR {amount:,.2f} (Risk Score: {risk_score}) at terminal {atm.atm_code}.",
                is_simulated=is_simulated
            )
            db.add(incident)
            await db.flush()

        await hub.emit_security_alert(
            alert_id=alert.id,
            title=alert.title,
            message=alert.message,
            severity="HIGH" if risk_level == "HIGH" else "CRITICAL",
            threat_type="SUSPICIOUS_TRANSACTION",
            atm_id=atm.id,
            account_id=account_id
        )

        return incident

    @classmethod
    async def handle_api_abuse(
        cls,
        db: AsyncSession,
        ip_address: str,
        endpoint: str,
        request_count: int,
        is_simulated: bool = False
    ) -> Alert:
        """Handles API rate limit violations and anomalous request floods."""
        event = SecurityEvent(
            type="API_ABUSE_RATE_LIMIT",
            severity=SeverityLevel.MEDIUM,
            source="RATE_LIMIT_MIDDLEWARE",
            ip_address=ip_address,
            details={
                "endpoint": endpoint,
                "requests": request_count,
                "action": "HTTP_429_TOO_MANY_REQUESTS"
            },
            is_simulated=is_simulated
        )
        db.add(event)
        await db.flush()

        alert = Alert(
            event_id=event.id,
            severity=SeverityLevel.MEDIUM,
            title=f"API Abuse Detected from {ip_address}",
            message=f"Rate limit exceeded on '{endpoint}' ({request_count} reqs in 5s). Temporary block enforced.",
            status=AlertStatus.NEW
        )
        db.add(alert)
        await db.flush()

        await hub.emit_security_alert(
            alert_id=alert.id,
            title=alert.title,
            message=alert.message,
            severity="MEDIUM",
            threat_type="API_ABUSE"
        )
        return alert

    @classmethod
    async def handle_unauthorized_access(
        cls,
        db: AsyncSession,
        actor_id: Optional[str],
        resource: str,
        attempt_type: str,
        ip_address: Optional[str] = None,
        is_simulated: bool = False
    ) -> Alert:
        """Handles IDOR, privilege escalation attempts, or unauthorized token access."""
        event = SecurityEvent(
            type="UNAUTHORIZED_ACCESS_ATTEMPT",
            severity=SeverityLevel.HIGH,
            source="ACCESS_CONTROL_GUARD",
            ip_address=ip_address,
            details={
                "actor_id": actor_id,
                "resource": resource,
                "attempt_type": attempt_type
            },
            is_simulated=is_simulated
        )
        db.add(event)
        await db.flush()

        alert = Alert(
            event_id=event.id,
            severity=SeverityLevel.HIGH,
            title=f"Unauthorized Access Attempt ({attempt_type})",
            message=f"Actor '{actor_id or 'anonymous'}' attempted unauthorized access to '{resource}'.",
            status=AlertStatus.NEW
        )
        db.add(alert)
        await db.flush()

        await hub.emit_security_alert(
            alert_id=alert.id,
            title=alert.title,
            message=alert.message,
            severity="HIGH",
            threat_type="UNAUTHORIZED_ACCESS"
        )
        return alert

    @classmethod
    async def handle_session_abuse(
        cls,
        db: AsyncSession,
        user_id: int,
        reason: str,
        is_simulated: bool = False
    ) -> Alert:
        """Handles reuse of revoked refresh tokens or post-logout session tokens."""
        event = SecurityEvent(
            type="SESSION_TOKEN_ABUSE",
            severity=SeverityLevel.HIGH,
            source="SESSION_SECURITY",
            user_id=user_id,
            details={"reason": reason},
            is_simulated=is_simulated
        )
        db.add(event)
        await db.flush()

        alert = Alert(
            event_id=event.id,
            severity=SeverityLevel.HIGH,
            title=f"Session Abuse / Token Replay Detected",
            message=f"User ID {user_id}: {reason}. Token family invalidated.",
            status=AlertStatus.NEW
        )
        db.add(alert)
        await db.flush()

        await hub.emit_security_alert(
            alert_id=alert.id,
            title=alert.title,
            message=alert.message,
            severity="HIGH",
            threat_type="SESSION_ABUSE"
        )
        return alert
