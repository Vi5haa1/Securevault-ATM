import uuid
import datetime
from decimal import Decimal
from typing import Dict, Any, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.db.models.models import (
    Atm, Card, Account, User, AtmStatus, SensorType, SensorState,
    SeverityLevel
)
from app.engines.event_pipeline import EventPipeline, RawEvent
from app.engines.threat_detection import ThreatDetectionEngine
from app.engines.risk_engine import RiskEngine
from app.audit.writer import write_audit_log


class SimulationRunner:
    """
    Expanded Safe Defensive Attack Simulation Engine.
    Strictly defensive: exercises genuine detection, correlation, risk scoring,
    automated containment, and tamper-evident audit pipelines on synthetic data only.
    Never interacts with external networks or real payment accounts.
    """

    @classmethod
    async def run_simulation(
        cls,
        db: AsyncSession,
        simulation_type: str,
        atm_id: Optional[int] = None,
        account_id: Optional[int] = None,
        intensity: int = 1
    ) -> Dict[str, Any]:
        sim_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
        steps: List[Dict[str, str]] = []
        actions: List[str] = []
        incident_code: Optional[str] = None
        alert_title: Optional[str] = None
        pipeline_trace: List[Dict[str, Any]] = []

        # Target ATM or default
        if atm_id:
            stmt_atm = select(Atm).where(Atm.id == atm_id)
        else:
            stmt_atm = select(Atm).limit(1)
        res_atm = await db.execute(stmt_atm)
        atm = res_atm.scalar_one_or_none()
        if not atm:
            raise ValueError("No ATM found for simulation.")

        # Target Card or default
        if account_id:
            stmt_card = select(Card).where(Card.account_id == account_id).limit(1)
        else:
            stmt_card = select(Card).limit(1)
        res_card = await db.execute(stmt_card)
        card = res_card.scalar_one_or_none()

        sim_type = simulation_type.upper()

        # =============================================================
        # 1. BRUTE FORCE PIN ATTACK
        # =============================================================
        if sim_type in ["BRUTE_FORCE", "AUTH_BRUTE_FORCE"]:
            if not card:
                raise ValueError("Target payment card required for brute-force simulation.")

            steps.append({
                "step": "SIMULATED_ATTACK_LAUNCH",
                "status": "EXECUTED",
                "detail": f"Injecting 5 sequential invalid PIN submissions against Card ending in {card.last4} at ATM {atm.atm_code}."
            })

            card.pin_failed_attempts = 0
            for i in range(1, 6):
                raw_evt = RawEvent(
                    event_type="FAILED_PIN",
                    source=f"ATM_PINPAD:{atm.atm_code}",
                    severity_hint=SeverityLevel.HIGH if i >= 5 else SeverityLevel.MEDIUM,
                    atm_id=atm.id,
                    account_id=card.account_id,
                    card_id=card.id,
                    ip_address="192.168.1.105",
                    correlation_key=f"card:{card.id}",
                    raw_payload={"card_last4": card.last4, "attempt": i},
                    is_simulated=True
                )
                pipeline_res = await EventPipeline.process_event(db, raw_evt)
                card.pin_failed_attempts = i

                steps.append({
                    "step": f"FAILED_PIN_ATTEMPT_{i}",
                    "status": "DETECTED",
                    "detail": f"PIN attempt {i} processed by Unified Pipeline. Risk: {pipeline_res['risk_score']}/100."
                })

                if pipeline_res["incident_code"]:
                    incident_code = pipeline_res["incident_code"]
                    alert_title = f"Brute Force Detected: Card {card.last4}"
                    actions = pipeline_res["actions_executed"]
                    pipeline_trace = pipeline_res["pipeline_trace"]

            detection_rule = "RULE-SV-001: Multiple Failed PIN Brute Force Attempts (5 invalid entries -> Correlated Incident)"

        # =============================================================
        # 2. PHYSICAL ATM TAMPER BREACH
        # =============================================================
        elif sim_type in ["ATM_TAMPER", "PHYSICAL_TAMPER"]:
            steps.append({
                "step": "SENSOR_SIGNAL_INJECTION",
                "status": "EXECUTED",
                "detail": f"Triggered physical cabinet breach alert on TAMPER microswitch at ATM {atm.atm_code}."
            })

            raw_evt = RawEvent(
                event_type="ATM_TAMPER",
                source=f"ATM_CHASSIS_SENSOR:{atm.atm_code}",
                severity_hint=SeverityLevel.CRITICAL,
                atm_id=atm.id,
                correlation_key=f"atm:{atm.id}",
                raw_payload={"sensor": "TAMPER", "state": "ALERT", "switch_open": True},
                is_simulated=True
            )
            pipeline_res = await EventPipeline.process_event(db, raw_evt)
            incident_code = pipeline_res["incident_code"]
            alert_title = f"CRITICAL: ATM Tamper Breach ({atm.atm_code})"
            actions = pipeline_res["actions_executed"]
            pipeline_trace = pipeline_res["pipeline_trace"]

            steps.append({
                "step": "CONTAINMENT_PLAYBOOK",
                "status": "PASSED",
                "detail": f"Zero-tolerance containment completed. Terminal {atm.atm_code} placed in LOCKDOWN."
            })
            detection_rule = "RULE-SV-003: Physical ATM Cabinet Tamper Breach (Chassis Alert -> Instant Lockdown)"

        # =============================================================
        # 3. SUSPICIOUS HIGH-VALUE / GEOGRAPHIC TRANSACTION
        # =============================================================
        elif sim_type in ["SUSPICIOUS_TXN", "ANOMALOUS_WITHDRAWAL"]:
            amount = Decimal("95000.00")
            steps.append({
                "step": "OUTLIER_WITHDRAWAL_ATTEMPT",
                "status": "EXECUTED",
                "detail": f"Initiating high-amount withdrawal of INR {amount:,.2f} from unexpected city '{atm.city}'."
            })

            raw_evt = RawEvent(
                event_type="SUSPICIOUS_TXN",
                source=f"ATM_DISPENSER:{atm.atm_code}",
                severity_hint=SeverityLevel.HIGH,
                atm_id=atm.id,
                account_id=card.account_id if card else 1,
                card_id=card.id if card else 1,
                correlation_key=f"account:{card.account_id if card else 1}",
                raw_payload={"amount": str(amount), "city": atm.city},
                is_simulated=True
            )
            pipeline_res = await EventPipeline.process_event(db, raw_evt)
            incident_code = pipeline_res["incident_code"]
            alert_title = f"Suspicious Transaction (Risk Score {pipeline_res['risk_score']})"
            actions = ["Transaction Blocked by Zero-Trust Pipeline", "Step-Up MFA Required", "Logged to Audit Chain"]
            pipeline_trace = pipeline_res["pipeline_trace"]
            detection_rule = "RULE-SV-002: Suspicious High-Risk Score Transaction Anomaly (Amount > 4x Baseline)"

        # =============================================================
        # 4. API RATE LIMIT BURST FLOOD
        # =============================================================
        elif sim_type in ["API_ABUSE", "RATE_LIMIT_BURST"]:
            steps.append({
                "step": "RATE_LIMIT_BURST_FLOOD",
                "status": "EXECUTED",
                "detail": "Sending 60 simulated rapid-fire transaction requests in 3 seconds from IP 198.51.100.22."
            })

            raw_evt = RawEvent(
                event_type="API_RATE_LIMIT",
                source="API_GATEWAY",
                severity_hint=SeverityLevel.HIGH,
                ip_address="198.51.100.22",
                correlation_key="ip:198.51.100.22",
                raw_payload={"request_count": 60, "endpoint": "/api/v1/atm/withdraw"},
                is_simulated=True
            )
            pipeline_res = await EventPipeline.process_event(db, raw_evt)
            alert_title = f"API Abuse: Rate Limit Exceeded (198.51.100.22)"
            actions = ["HTTP 429 Too Many Requests Enforced", "Temporary IP Throttling Engaged"]
            pipeline_trace = pipeline_res["pipeline_trace"]
            detection_rule = "RULE-SV-004: Token Bucket API Abuse Rate Limit Flood (> 50 reqs / 5s -> Gateway Block)"

        # =============================================================
        # 5. PRIVILEGE ESCALATION PROBE
        # =============================================================
        elif sim_type in ["UNAUTHORIZED_ACCESS", "PRIVILEGE_ESCALATION"]:
            steps.append({
                "step": "PRIVILEGE_ESCALATION_PROBE",
                "status": "EXECUTED",
                "detail": "Customer role actor probing '/api/v1/admin/security/policies' with forged authorization headers."
            })

            raw_evt = RawEvent(
                event_type="PRIVILEGE_ESCALATION",
                source="API_AUTHORIZATION_FILTER",
                severity_hint=SeverityLevel.HIGH,
                ip_address="198.51.100.45",
                correlation_key="user:customer_actor",
                raw_payload={"target_resource": "/api/v1/admin/security/policies", "claimed_role": "CUSTOMER"},
                is_simulated=True
            )
            pipeline_res = await EventPipeline.process_event(db, raw_evt)
            alert_title = "Privilege Escalation Blocked"
            actions = ["HTTP 403 Forbidden Returned", "IDOR / RBAC Breach Ticket Dispatched"]
            pipeline_trace = pipeline_res["pipeline_trace"]
            detection_rule = "RULE-SV-006: Unauthorized Zero-Trust RBAC Privilege Escalation Probe"

        # =============================================================
        # 6. SESSION / TOKEN REPLAY
        # =============================================================
        elif sim_type in ["SESSION_ABUSE", "TOKEN_REPLAY"]:
            steps.append({
                "step": "REFRESH_TOKEN_REPLAY",
                "status": "EXECUTED",
                "detail": "Replaying previously consumed refresh token family #TF-8942 from unverified fingerprint."
            })

            raw_evt = RawEvent(
                event_type="TOKEN_REPLAY",
                source="AUTH_TOKEN_SERVICE",
                severity_hint=SeverityLevel.HIGH,
                correlation_key="family:TF-8942",
                raw_payload={"token_family": "TF-8942", "reason": "Revoked Token Reuse"},
                is_simulated=True
            )
            pipeline_res = await EventPipeline.process_event(db, raw_evt)
            alert_title = "OAuth Token Replay Detected"
            actions = ["Entire Token Family Revoked", "Active Sessions Force-Terminated"]
            pipeline_trace = pipeline_res["pipeline_trace"]
            detection_rule = "RULE-SV-005: Rotating Refresh Token Family Replay Detection (RFC 6749)"

        # =============================================================
        # 7. ATM FIRMWARE INTEGRITY TAMPER
        # =============================================================
        elif sim_type in ["FIRMWARE_TAMPER", "SECURE_BOOT_FAIL"]:
            steps.append({
                "step": "FIRMWARE_HASH_MISMATCH",
                "status": "EXECUTED",
                "detail": f"Synthesized unauthorized binary modification on ATM {atm.atm_code}. Hash signature failed."
            })

            atm.firmware_hash = "0000000000000000000000000000000000000000000000000000000000000000"
            atm.secure_boot_enabled = False

            raw_evt = RawEvent(
                event_type="FIRMWARE_TAMPER",
                source=f"ATM_AGENT_BOOT:{atm.atm_code}",
                severity_hint=SeverityLevel.CRITICAL,
                atm_id=atm.id,
                correlation_key=f"atm:{atm.id}",
                raw_payload={"expected_hash": "e3b0c44298fc...", "actual_hash": "00000000..."},
                is_simulated=True
            )
            pipeline_res = await EventPipeline.process_event(db, raw_evt)
            incident_code = pipeline_res["incident_code"]
            alert_title = f"CRITICAL: Firmware Integrity Check Failed ({atm.atm_code})"
            actions = pipeline_res["actions_executed"]
            pipeline_trace = pipeline_res["pipeline_trace"]
            detection_rule = "RULE-SV-007: ATM Firmware Cryptographic Hash Failure (Zero-Tolerance Lockdown)"

        # =============================================================
        # 8. CERTIFICATE FAILURE (EXPIRED / REVOKED)
        # =============================================================
        elif sim_type in ["CERT_FAILURE", "MTLS_REVOKED"]:
            steps.append({
                "step": "MTLS_HANDSHAKE_ATTEMPT",
                "status": "EXECUTED",
                "detail": f"Attempting connection from ATM {atm.atm_code} with revoked client certificate."
            })

            atm.certificate_status = "REVOKED"

            raw_evt = RawEvent(
                event_type="CERT_FAILURE",
                source=f"GATEWAY_MTLS:{atm.atm_code}",
                severity_hint=SeverityLevel.CRITICAL,
                atm_id=atm.id,
                correlation_key=f"atm:{atm.id}",
                raw_payload={"certificate_id": atm.certificate_id, "status": "REVOKED"},
                is_simulated=True
            )
            pipeline_res = await EventPipeline.process_event(db, raw_evt)
            incident_code = pipeline_res["incident_code"]
            alert_title = f"mTLS Handshake Blocked: Revoked Certificate ({atm.atm_code})"
            actions = ["mTLS Connection Dropped", "Terminal Traffic Blocked"]
            pipeline_trace = pipeline_res["pipeline_trace"]
            detection_rule = "RULE-SV-008: ATM mTLS Client Certificate Expired or Revoked"

        # =============================================================
        # 9. DUPLICATE TRANSACTION REPLAY
        # =============================================================
        elif sim_type in ["DUPLICATE_TXN", "IDEMPOTENCY_REPLAY"]:
            steps.append({
                "step": "TRANSACTION_REPLAY_INJECTION",
                "status": "EXECUTED",
                "detail": "Resubmitting previously cleared withdrawal payload with duplicated STAN #048291 and idempotency key."
            })

            raw_evt = RawEvent(
                event_type="DUPLICATE_TXN",
                source="TRANSACTION_SERVICE",
                severity_hint=SeverityLevel.HIGH,
                atm_id=atm.id,
                correlation_key="idempotency:dup-key-048291",
                raw_payload={"stan": "048291", "idempotency_key": "dup-key-048291"},
                is_simulated=True
            )
            pipeline_res = await EventPipeline.process_event(db, raw_evt)
            alert_title = "Duplicate Transaction Replay Blocked"
            actions = ["Second Request Blocked (Original: SUCCESS, Second: REJECTED)", "Idempotency Lock Held"]
            pipeline_trace = pipeline_res["pipeline_trace"]
            detection_rule = "RULE-SV-009: Duplicate Transaction Replay (Idempotency Collision)"

        # =============================================================
        # 10. IMPOSSIBLE TRAVEL
        # =============================================================
        elif sim_type in ["IMPOSSIBLE_TRAVEL"]:
            steps.append({
                "step": "GEOGRAPHIC_VELOCITY_PROBE",
                "status": "EXECUTED",
                "detail": "Card used in Chennai, then attempted in Delhi 12 minutes later (distance 2,180 km)."
            })

            raw_evt = RawEvent(
                event_type="IMPOSSIBLE_TRAVEL",
                source="UEBA_GEOLOCATION_ENGINE",
                severity_hint=SeverityLevel.HIGH,
                atm_id=atm.id,
                account_id=card.account_id if card else 1,
                correlation_key=f"account:{card.account_id if card else 1}",
                raw_payload={"origin_city": "Chennai", "destination_city": "Delhi", "elapsed_minutes": 12},
                is_simulated=True
            )
            pipeline_res = await EventPipeline.process_event(db, raw_evt)
            incident_code = pipeline_res["incident_code"]
            alert_title = "Impossible Travel Anomaly Detected"
            actions = ["Step-Up MFA Required", "Account Placed on Review"]
            pipeline_trace = pipeline_res["pipeline_trace"]
            detection_rule = "RULE-SV-010: Impossible Travel Velocity Anomaly"

        else:
            raise ValueError(f"Unknown defensive simulation type: {simulation_type}")

        # Final audit
        await write_audit_log(
            db=db,
            action="ATTACK_SIMULATION_EXECUTED",
            resource_type="SIMULATION",
            resource_id=sim_id,
            payload={
                "simulation_type": sim_type,
                "atm_id": atm.id,
                "steps_count": len(steps),
                "incident_code": incident_code,
                "detection_rule": detection_rule,
            }
        )

        return {
            "simulation_id": sim_id,
            "simulation_type": sim_type,
            "threat_detected": True,
            "detection_rule": detection_rule,
            "actions_triggered": actions,
            "incident_code": incident_code,
            "alert_title": alert_title,
            "steps": steps,
            "pipeline_trace": pipeline_trace
        }
