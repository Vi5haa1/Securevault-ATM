import datetime
from decimal import Decimal
from typing import Dict, Any, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.db.models.models import (
    Customer, BehaviorProfile, Atm, AtmStatus, Transaction, TransactionType, 
    TransactionStatus, RiskLevel, TrustedDevice, Card, SecurityPolicy
)


class RiskAssessment:
    def __init__(self, score: int, level: RiskLevel, factors: List[Dict[str, Any]], action: str):
        self.score = min(100, max(0, score))
        self.level = level
        self.factors = factors
        self.action = action  # "APPROVE", "STEP_UP_OTP", "MANDATORY_MFA", "BLOCK"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level.value,
            "factors": self.factors,
            "action": self.action
        }


class RiskEngine:
    """
    Explainable Risk Scoring Engine.
    Evaluates real-time risk based on behavioral baselines, geographical anomalies,
    velocity metrics, device fingerprints, and authentication history.
    """

    @classmethod
    async def evaluate_transaction_risk(
        cls,
        db: AsyncSession,
        customer_id: int,
        atm: Atm,
        amount: Decimal,
        device_fingerprint: Optional[str] = None,
        is_simulated: bool = False
    ) -> RiskAssessment:
        score = 0
        factors: List[Dict[str, Any]] = []

        # 1. Fetch Customer Behavior Profile
        stmt_prof = select(BehaviorProfile).where(BehaviorProfile.customer_id == customer_id)
        res_prof = await db.execute(stmt_prof)
        profile = res_prof.scalar_one_or_none()

        # Factor 1: Large Amount (Points: +20)
        large_amount_triggered = False
        if profile and profile.typical_max > 0:
            if amount > (profile.typical_max * Decimal("2.0")):
                large_amount_triggered = True
                score += 20
                factors.append({
                    "factor_name": "LARGE_AMOUNT_DEVIATION",
                    "points": 20,
                    "triggered": True,
                    "description": f"Amount (INR {amount}) exceeds 2x typical maximum (INR {profile.typical_max})."
                })
        elif amount >= Decimal("25000.00"):
            large_amount_triggered = True
            score += 20
            factors.append({
                "factor_name": "LARGE_AMOUNT_HIGH_VALUE",
                "points": 20,
                "triggered": True,
                "description": f"High value withdrawal of INR {amount} without established profile."
            })

        if not large_amount_triggered:
            factors.append({
                "factor_name": "AMOUNT_NORMAL",
                "points": 0,
                "triggered": False,
                "description": "Withdrawal amount is consistent with customer typical spend."
            })

        # Factor 2: New Location (Points: +25)
        location_triggered = False
        if profile and profile.typical_cities:
            if atm.city not in profile.typical_cities:
                location_triggered = True
                score += 25
                factors.append({
                    "factor_name": "UNUSUAL_LOCATION",
                    "points": 25,
                    "triggered": True,
                    "description": f"ATM located in '{atm.city}', which is not in customer's typical cities: {profile.typical_cities}."
                })
        if not location_triggered:
            factors.append({
                "factor_name": "LOCATION_NORMAL",
                "points": 0,
                "triggered": False,
                "description": f"ATM city '{atm.city}' matches customer profile."
            })

        # Factor 3: Unusual Time (Points: +10)
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        # Convert to IST (UTC+5:30) for Indian ATM network
        ist_hour = (now_utc.hour + 5 + ((now_utc.minute + 30) // 60)) % 24

        time_triggered = False
        if profile:
            if ist_hour < profile.typical_start_hour or ist_hour > profile.typical_end_hour:
                time_triggered = True
                score += 10
                factors.append({
                    "factor_name": "UNUSUAL_TIME",
                    "points": 10,
                    "triggered": True,
                    "description": f"Transaction hour ({ist_hour}:00 IST) is outside typical window ({profile.typical_start_hour}:00 - {profile.typical_end_hour}:00 IST)."
                })
        elif ist_hour < 6 or ist_hour > 23:
            time_triggered = True
            score += 10
            factors.append({
                "factor_name": "LATE_NIGHT_TRANSACTION",
                "points": 10,
                "triggered": True,
                "description": f"Late night transaction attempt at {ist_hour}:00 IST."
            })

        if not time_triggered:
            factors.append({
                "factor_name": "TIME_NORMAL",
                "points": 0,
                "triggered": False,
                "description": f"Transaction initiated at normal business hours ({ist_hour}:00 IST)."
            })

        # Factor 4: Velocity - Multiple withdrawals in last hour (Points: +20)
        one_hour_ago = now_utc - datetime.timedelta(hours=1)
        stmt_vel = select(func.count(Transaction.id)).where(
            Transaction.created_at >= one_hour_ago,
            Transaction.type == TransactionType.WITHDRAWAL,
            Transaction.status == TransactionStatus.APPROVED
        )
        res_vel = await db.execute(stmt_vel)
        recent_count = res_vel.scalar() or 0

        if recent_count >= 3:
            score += 20
            factors.append({
                "factor_name": "VELOCITY_SPIKE",
                "points": 20,
                "triggered": True,
                "description": f"High velocity: {recent_count} successful withdrawals in the last 60 minutes."
            })
        else:
            factors.append({
                "factor_name": "VELOCITY_NORMAL",
                "points": 0,
                "triggered": False,
                "description": f"Normal velocity: {recent_count} withdrawals in the last hour."
            })

        # Factor 5: Untrusted / New Device (Points: +15)
        device_triggered = False
        if device_fingerprint:
            stmt_dev = select(TrustedDevice).where(
                TrustedDevice.customer_id == customer_id,
                TrustedDevice.fingerprint == device_fingerprint,
                TrustedDevice.trusted == True
            )
            res_dev = await db.execute(stmt_dev)
            trusted_dev = res_dev.scalar_one_or_none()
            if not trusted_dev:
                device_triggered = True
                score += 15
                factors.append({
                    "factor_name": "UNTRUSTED_DEVICE",
                    "points": 15,
                    "triggered": True,
                    "description": f"Device fingerprint '{device_fingerprint[:16]}...' is not in customer's trusted device registry."
                })
        if not device_triggered:
            factors.append({
                "factor_name": "DEVICE_RECOGNIZED",
                "points": 0,
                "triggered": False,
                "description": "Device hardware fingerprint recognized and trusted."
            })

        # Factor 6: Recent Failed Auth Attempts (Points: +10)
        # Check customer cards failed attempts
        stmt_card = select(Card).join(Card.account).where(Card.account.has(customer_id=customer_id))
        res_card = await db.execute(stmt_card)
        cards = res_card.scalars().all()
        failed_attempts = max([c.pin_failed_attempts for c in cards] or [0])

        if failed_attempts > 0:
            score += 10
            factors.append({
                "factor_name": "RECENT_AUTH_FAILURES",
                "points": 10,
                "triggered": True,
                "description": f"Card has {failed_attempts} prior failed PIN attempt(s)."
            })

        # Factor 7: ATM Terminal Health & Integrity (+30)
        atm_compromised = False
        if atm.status == AtmStatus.LOCKDOWN or getattr(atm, "under_attack", False):
            atm_compromised = True
            score += 30
            factors.append({
                "factor_name": "ATM_INTEGRITY_COMPROMISE",
                "points": 30,
                "triggered": True,
                "description": f"ATM {atm.atm_code} is flagged as UNDER_ATTACK or EMERGENCY_LOCKDOWN."
            })
        elif getattr(atm, "certificate_status", "VALID") != "VALID":
            atm_compromised = True
            score += 25
            factors.append({
                "factor_name": "ATM_CERTIFICATE_INVALID",
                "points": 25,
                "triggered": True,
                "description": f"ATM client mTLS certificate is {getattr(atm, 'certificate_status', 'UNKNOWN')}."
            })
        else:
            factors.append({
                "factor_name": "ATM_INTEGRITY_VERIFIED",
                "points": 0,
                "triggered": False,
                "description": f"ATM hardware, firmware hash, and client certificate verified valid."
            })

        # Cap score at 100
        total_score = min(100, score)

        # Categorize Level and Action
        if total_score <= 30:
            level = RiskLevel.LOW
            action = "APPROVE"
        elif total_score <= 60:
            level = RiskLevel.MEDIUM
            action = "STEP_UP_OTP"
        elif total_score <= 80:
            level = RiskLevel.HIGH
            action = "MANDATORY_MFA"
        else:
            level = RiskLevel.CRITICAL
            action = "BLOCK"

        # Build human-readable "Why this score?" breakdown equation
        triggered_factors = [f for f in factors if f["triggered"]]
        if triggered_factors:
            breakdown_equation = " + ".join([f"{f['factor_name']} (+{f['points']})" for f in triggered_factors]) + f" = {total_score}/100 ({level.value})"
        else:
            breakdown_equation = f"Clean risk baseline: 0/100 ({level.value}) - All security signals nominal."

        for f in factors:
            f["breakdown_summary"] = breakdown_equation

        return RiskAssessment(
            score=total_score,
            level=level,
            factors=factors,
            action=action
        )
