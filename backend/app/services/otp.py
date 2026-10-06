import secrets
import hashlib
import datetime
from typing import Tuple, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.db.models.models import OtpChallenge, User, Card
from app.core.security import constant_time_compare


class OtpService:
    @staticmethod
    def generate_otp_code() -> str:
        """Generates a secure 6-digit numeric OTP."""
        return f"{secrets.randbelow(1000000):06d}"

    @classmethod
    async def create_challenge(
        cls,
        db: AsyncSession,
        user_id: int,
        card_id: Optional[int] = None,
        purpose: str = "ATM_VERIFICATION",
        validity_minutes: int = 2
    ) -> Tuple[int, str]:
        """
        Creates an ephemeral OTP challenge in the database.
        Returns (challenge_id, plain_otp_code).
        Only the SHA-256 hash is saved to the database.
        """
        code = cls.generate_otp_code()
        code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
        expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=validity_minutes)

        challenge = OtpChallenge(
            user_id=user_id,
            card_id=card_id,
            code_hash=code_hash,
            expires_at=expires_at,
            attempts=0,
            consumed=False,
            purpose=purpose
        )
        db.add(challenge)
        await db.flush()
        return challenge.id, code

    @classmethod
    async def verify_challenge(
        cls,
        db: AsyncSession,
        challenge_id: int,
        provided_code: str
    ) -> Tuple[bool, str]:
        """
        Verifies an OTP challenge:
        - Must exist and not already consumed
        - Must not be expired (2 minutes)
        - Max 3 attempts
        - Constant-time hash comparison
        """
        stmt = select(OtpChallenge).where(OtpChallenge.id == challenge_id)
        result = await db.execute(stmt)
        challenge = result.scalar_one_or_none()

        if not challenge:
            return False, "OTP challenge not found."

        if challenge.consumed:
            return False, "OTP has already been used."

        now = datetime.datetime.now(datetime.timezone.utc)
        expires_at = challenge.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)

        if expires_at < now:
            return False, "OTP has expired. Please request a new one."

        if challenge.attempts >= 3:
            return False, "Maximum OTP verification attempts exceeded."

        challenge.attempts += 1
        computed_hash = hashlib.sha256(provided_code.encode("utf-8")).hexdigest()

        if constant_time_compare(computed_hash, challenge.code_hash):
            challenge.consumed = True
            await db.flush()
            return True, "OTP verified successfully."
        else:
            await db.flush()
            remaining = 3 - challenge.attempts
            return False, f"Invalid OTP code. {remaining} attempt(s) remaining."
