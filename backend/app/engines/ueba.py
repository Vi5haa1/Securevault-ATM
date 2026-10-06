import datetime
import logging
from typing import Dict, Any, List, Optional, Tuple
from decimal import Decimal
import pandas as pd
import numpy as np
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func

from app.db.models.models import Customer, Account, Transaction, Atm, BehaviorProfile, TrustedDevice

logger = logging.getLogger("securevault.ueba")


class UEBAResult:
    def __init__(
        self,
        anomaly_score: int,
        classification: str,  # NORMAL, ANOMALOUS, HIGHLY_ANOMALOUS
        contributions: Dict[str, int],
        explanation: str,
        user_baseline: Dict[str, Any],
        observed_signals: Dict[str, Any]
    ):
        self.anomaly_score = anomaly_score
        self.classification = classification
        self.contributions = contributions
        self.explanation = explanation
        self.user_baseline = user_baseline
        self.observed_signals = observed_signals

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_score": self.anomaly_score,
            "classification": self.classification,
            "contributions": self.contributions,
            "explanation": self.explanation,
            "user_baseline": self.user_baseline,
            "observed_signals": self.observed_signals
        }


class UEBAEngine:
    """
    User & Entity Behavior Analytics (UEBA) Engine
    Uses statistical distributions (mean, std, percentiles) over 60-day historical activity
    to detect behavioral shifts across Amount, Operating Hours, Geography, Device, and Terminal.
    Guards against baseline poisoning by excluding flagged/simulated transactions from training updates.
    """

    @classmethod
    async def evaluate_transaction_behavior(
        cls,
        db: AsyncSession,
        customer_id: int,
        atm: Atm,
        amount: Decimal,
        device_fingerprint: Optional[str] = None,
        txn_timestamp: Optional[datetime.datetime] = None
    ) -> UEBAResult:
        timestamp = txn_timestamp or datetime.datetime.now(datetime.timezone.utc)
        current_hour = timestamp.hour
        amt_float = float(amount)

        # 1. Fetch Customer Behavior Profile
        stmt_prof = select(BehaviorProfile).where(BehaviorProfile.customer_id == customer_id)
        res_prof = await db.execute(stmt_prof)
        profile = res_prof.scalar_one_or_none()

        if not profile:
            # Cold-start baseline defaults
            profile = BehaviorProfile(
                customer_id=customer_id,
                avg_withdrawal=Decimal("3000.00"),
                std_withdrawal=Decimal("1500.00"),
                typical_min=Decimal("500.00"),
                typical_max=Decimal("8000.00"),
                typical_start_hour=8,
                typical_end_hour=21,
                typical_cities=[atm.city],
                txn_per_week_avg=Decimal("3.5")
            )

        avg_w = float(profile.avg_withdrawal)
        std_w = max(float(profile.std_withdrawal), 500.0)
        min_w = float(profile.typical_min)
        max_w = float(profile.typical_max)
        typical_cities = profile.typical_cities or [atm.city]

        contributions: Dict[str, int] = {}
        explanation_clauses: List[str] = []

        # --- A. Amount Anomaly (Z-score & Range) ---
        z_score = (amt_float - avg_w) / std_w
        if amt_float > max_w * 3:
            amt_contrib = 40
            explanation_clauses.append(f"Amount INR {amt_float:,.2f} is extreme outlier (>3x typical ceiling INR {max_w:,.2f}, z-score: {z_score:.2f})")
        elif amt_float > max_w:
            amt_contrib = int(min(30, max(10, z_score * 10)))
            explanation_clauses.append(f"Amount INR {amt_float:,.2f} exceeds normal range (typical max: INR {max_w:,.2f})")
        elif amt_float < min_w * 0.3:
            amt_contrib = 10
            explanation_clauses.append(f"Micro-withdrawal INR {amt_float:,.2f} below normal floor")
        else:
            amt_contrib = 0

        contributions["amount_deviation"] = amt_contrib

        # --- B. Time-of-Day Anomaly ---
        hour_contrib = 0
        if current_hour < profile.typical_start_hour or current_hour > profile.typical_end_hour:
            # Check nocturnal window (12 AM - 5 AM)
            if 0 <= current_hour <= 5:
                hour_contrib = 25
                explanation_clauses.append(f"Nocturnal operation at {current_hour:02d}:00 (usual active hours: {profile.typical_start_hour:02d}:00-{profile.typical_end_hour:02d}:00)")
            else:
                hour_contrib = 15
                explanation_clauses.append(f"Off-hours transaction at {current_hour:02d}:00")

        contributions["time_anomaly"] = hour_contrib

        # --- C. Geographic Anomaly ---
        geo_contrib = 0
        if atm.city not in typical_cities:
            geo_contrib = 30
            explanation_clauses.append(f"Foreign city '{atm.city}' (home/normal cluster: {', '.join(typical_cities)})")

        contributions["location_deviation"] = geo_contrib

        # --- D. Device & Terminal Trust ---
        dev_contrib = 0
        if device_fingerprint:
            stmt_dev = select(TrustedDevice).where(
                and_(
                    TrustedDevice.customer_id == customer_id,
                    TrustedDevice.fingerprint == device_fingerprint,
                    TrustedDevice.trusted == True
                )
            )
            res_dev = await db.execute(stmt_dev)
            if not res_dev.scalar_one_or_none():
                dev_contrib = 15
                explanation_clauses.append("Unrecognized client device / terminal probe fingerprint")

        contributions["untrusted_device"] = dev_contrib

        # --- Aggregate Score ---
        raw_score = sum(contributions.values())
        final_score = min(100, raw_score)

        if final_score >= 70:
            classification = "HIGHLY_ANOMALOUS"
        elif final_score >= 35:
            classification = "ANOMALOUS"
        else:
            classification = "NORMAL"

        if not explanation_clauses:
            full_explanation = f"Consistent with historical baseline: amount INR {amt_float:,.2f} within normal range (INR {min_w:,.2f}-{max_w:,.2f}) in {atm.city}."
        else:
            full_explanation = "; ".join(explanation_clauses) + f" -> Anomaly Score: {final_score} ({classification})."

        return UEBAResult(
            anomaly_score=final_score,
            classification=classification,
            contributions=contributions,
            explanation=full_explanation,
            user_baseline={
                "typical_amount_range": f"INR {min_w:,.2f} - INR {max_w:,.2f}",
                "mean_withdrawal": avg_w,
                "std_withdrawal": std_w,
                "typical_hours": f"{profile.typical_start_hour:02d}:00 - {profile.typical_end_hour:02d}:00",
                "normal_cities": typical_cities
            },
            observed_signals={
                "current_amount": amt_float,
                "current_hour": f"{current_hour:02d}:00",
                "terminal_city": atm.city,
                "atm_code": atm.atm_code
            }
        )

    @classmethod
    async def update_customer_baselines(cls, db: AsyncSession, customer_id: int):
        """
        Incrementally recalculates user baselines using pandas.
        Guards against baseline poisoning by excluding flagged/simulated/blocked transactions.
        """
        # Fetch clean approved transactions for this customer
        stmt_tx = (
            select(Transaction)
            .join(Account, Account.id == Transaction.account_id)
            .where(
                and_(
                    Account.customer_id == customer_id,
                    Transaction.status == "APPROVED",
                    Transaction.is_simulated == False,
                    Transaction.risk_score < 50
                )
            )
            .order_by(Transaction.created_at.desc())
            .limit(100)
        )
        res_tx = await db.execute(stmt_tx)
        txns = res_tx.scalars().all()

        if len(txns) < 3:
            return  # Not enough clean data points

        df = pd.DataFrame([
            {"amount": float(t.amount), "hour": t.created_at.hour}
            for t in txns
        ])

        avg_amt = float(df["amount"].mean())
        std_amt = float(df["amount"].std()) if len(df) > 1 else 1000.0
        q10 = float(df["amount"].quantile(0.10))
        q90 = float(df["amount"].quantile(0.90))

        stmt_prof = select(BehaviorProfile).where(BehaviorProfile.customer_id == customer_id)
        res_prof = await db.execute(stmt_prof)
        prof = res_prof.scalar_one_or_none()

        if prof:
            prof.avg_withdrawal = Decimal(f"{avg_amt:.2f}")
            prof.std_withdrawal = Decimal(f"{std_amt:.2f}")
            prof.typical_min = Decimal(f"{max(100.0, q10):.2f}")
            prof.typical_max = Decimal(f"{max(2000.0, q90):.2f}")
            prof.updated_at = datetime.datetime.now(datetime.timezone.utc)
            await db.commit()
