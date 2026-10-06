from typing import Optional
from pydantic import BaseModel, Field, EmailStr
from app.db.models.models import UserRole


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    role: UserRole
    username: str
    requires_otp: bool = False
    otp_challenge_id: Optional[int] = None
    session_token: Optional[str] = None


class StaffLoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=8, max_length=128)
    totp_code: Optional[str] = Field(None, min_length=6, max_length=6)


class CustomerAtmLoginRequest(BaseModel):
    card_number: str = Field(..., min_length=16, max_length=19)
    pin: str = Field(..., min_length=4, max_length=6)
    atm_id: int
    device_fingerprint: Optional[str] = "web-kiosk-default"


class VerifyOtpRequest(BaseModel):
    otp_code: str = Field(..., min_length=6, max_length=6)
    challenge_id: int
    device_fingerprint: Optional[str] = "web-kiosk-default"


class ChangePinRequest(BaseModel):
    current_pin: str = Field(..., min_length=4, max_length=6)
    new_pin: str = Field(..., min_length=4, max_length=6)
    confirm_pin: str = Field(..., min_length=4, max_length=6)
    otp_code: Optional[str] = Field(None, min_length=6, max_length=6)


class TotpSetupResponse(BaseModel):
    secret: str
    provisioning_uri: str
    qr_code_base64: str


class TotpVerifyRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=6)


class SessionHeartbeatResponse(BaseModel):
    active: bool
    remaining_seconds: int
