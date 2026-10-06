import datetime
from decimal import Decimal
from typing import Optional, List, Dict, Any
import numpy as np
import pandas as pd
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.models.models import (
    Customer, BehaviorProfile, Transaction, TransactionType, TransactionStatus, Atm
)


class BehaviorEngine:
    """
    Statistical Behavioral Analysis Engine.
    Leverages pandas and numpy to compute baseline metrics (mean, std, min, max,
    typical activity hours, typical cities, weekly frequency) from approved historical transactions.
    """

    @classmethod
    async def recompute_customer_profile(
        cls,
        db: AsyncSession,
        customer_id: int
    ) -> Optional[BehaviorProfile]:
        # Fetch all approved transactions for this customer
        stmt = (
            select(Transaction, Atm)
            .join(Atm, Transaction.atm_id == Atm.id)
            .join(Transaction.account)
            .where(
                Transaction.account.has(customer_id=customer_id),
                Transaction.status == TransactionStatus.APPROVED,
                Transaction.type.in_([TransactionType.WITHDRAWAL, TransactionType.TRANSFER])
            )
        )
        res = await db.execute(stmt)
        rows = res.all()

        if not rows:
            # No transactions yet, fetch or create default profile
            stmt_p = select(BehaviorProfile).where(BehaviorProfile.customer_id == customer_id)
            res_p = await db.execute(stmt_p)
            profile = res_p.scalar_one_or_none()
            if not profile:
                # Get customer home city
                stmt_c = select(Customer).where(Customer.id == customer_id)
                res_c = await db.execute(stmt_c)
                cust = res_c.scalar_one_or_none()
                home_city = cust.home_city if cust else "Mumbai"

                profile = BehaviorProfile(
                    customer_id=customer_id,
                    avg_withdrawal=Decimal("2500.00"),
                    std_withdrawal=Decimal("1200.00"),
                    typical_min=Decimal("500.00"),
                    typical_max=Decimal("5000.00"),
                    typical_start_hour=7,
                    typical_end_hour=22,
                    typical_cities=[home_city],
                    txn_per_week_avg=Decimal("3.00")
                )
                db.add(profile)
                await db.flush()
            return profile

        # Build DataFrame
        data = []
        for txn, atm in rows:
            data.append({
                "amount": float(txn.amount),
                "created_at": txn.created_at,
                "hour": txn.created_at.hour,
                "city": atm.city
            })
        df = pd.DataFrame(data)

        # Statistical calculations
        amounts = df["amount"].values
        avg_amt = float(np.mean(amounts))
        std_amt = float(np.std(amounts)) if len(amounts) > 1 else avg_amt * 0.5
        min_amt = float(np.percentile(amounts, 10)) if len(amounts) >= 5 else float(np.min(amounts))
        max_amt = float(np.percentile(amounts, 90)) if len(amounts) >= 5 else float(np.max(amounts))

        # Typical hours (10th to 90th percentile of hours)
        hours = df["hour"].values
        start_hour = int(np.percentile(hours, 10)) if len(hours) >= 5 else int(np.min(hours))
        end_hour = int(np.percentile(hours, 90)) if len(hours) >= 5 else int(np.max(hours))
        if start_hour == end_hour:
            start_hour = max(0, start_hour - 3)
            end_hour = min(23, end_hour + 3)

        # Typical cities (cities with at least 15% of transactions)
        city_counts = df["city"].value_counts(normalize=True)
        frequent_cities = city_counts[city_counts >= 0.15].index.tolist()
        if not frequent_cities:
            frequent_cities = df["city"].unique().tolist()

        # Weekly frequency
        time_span_days = max(1.0, (df["created_at"].max() - df["created_at"].min()).total_seconds() / 86400.0)
        weeks = max(1.0, time_span_days / 7.0)
        weekly_avg = float(len(df) / weeks)

        # Update or create profile in DB
        stmt_p = select(BehaviorProfile).where(BehaviorProfile.customer_id == customer_id)
        res_p = await db.execute(stmt_p)
        profile = res_p.scalar_one_or_none()

        if not profile:
            profile = BehaviorProfile(customer_id=customer_id)
            db.add(profile)

        profile.avg_withdrawal = Decimal(f"{avg_amt:.2f}")
        profile.std_withdrawal = Decimal(f"{std_amt:.2f}")
        profile.typical_min = Decimal(f"{min_amt:.2f}")
        profile.typical_max = Decimal(f"{max_amt:.2f}")
        profile.typical_start_hour = max(0, min(23, start_hour))
        profile.typical_end_hour = max(0, min(23, end_hour))
        profile.typical_cities = frequent_cities
        profile.txn_per_week_avg = Decimal(f"{weekly_avg:.2f}")
        profile.updated_at = datetime.datetime.now(datetime.timezone.utc)

        await db.flush()
        return profile
