import datetime
import hashlib
import hmac
import base64
from typing import Optional, Dict, Any, Union
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from cryptography.fernet import Fernet
from app.core.config import settings

# Initialize Argon2id password hasher with secure parameters
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MB
    parallelism=2,
    hash_len=32,
    salt_len=16
)


def get_fernet() -> Fernet:
    """Returns a Fernet cipher instance using the configured key."""
    # Ensure key is valid 32-byte base64
    key = settings.FERNET_KEY
    if len(key) != 44:
        # Generate deterministic 32-byte urlsafe base64 from whatever key string was configured
        padded = hashlib.sha256(key.encode()).digest()
        key = base64.urlsafe_b64encode(padded).decode()
    return Fernet(key.encode())


def hash_password(password: str) -> str:
    """Hashes a password using Argon2id."""
    return ph.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a password hash using Argon2id."""
    try:
        return ph.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError):
        return False


def hash_pin(pin: str) -> str:
    """Hashes an ATM PIN with a server-side pepper and Argon2id."""
    peppered = f"{settings.PIN_PEPPER}:{pin}"
    return ph.hash(peppered)


def verify_pin(plain_pin: str, hashed_pin: str) -> bool:
    """Verifies a peppered ATM PIN with Argon2id."""
    peppered = f"{settings.PIN_PEPPER}:{plain_pin}"
    try:
        return ph.verify(hashed_pin, peppered)
    except (VerifyMismatchError, VerificationError):
        return False


def hash_card_number(card_number: str) -> str:
    """Deterministic HMAC-SHA256 hash of card number for DB lookup."""
    clean_num = card_number.replace(" ", "").replace("-", "")
    return hmac.new(settings.SECRET_KEY.encode(), clean_num.encode(), hashlib.sha256).hexdigest()


def extract_last4(card_number: str) -> str:
    """Extracts last 4 digits of a card number."""
    clean_num = card_number.replace(" ", "").replace("-", "")
    return clean_num[-4:] if len(clean_num) >= 4 else clean_num


def encrypt_mfa_secret(secret: str) -> str:
    """Encrypts TOTP secret key using Fernet."""
    f = get_fernet()
    return f.encrypt(secret.encode()).decode()


def decrypt_mfa_secret(encrypted_secret: str) -> str:
    """Decrypts TOTP secret key using Fernet."""
    f = get_fernet()
    return f.decrypt(encrypted_secret.encode()).decode()


def create_access_token(
    subject: Union[str, int],
    role: str,
    expires_delta: Optional[datetime.timedelta] = None,
    extra_claims: Optional[Dict[str, Any]] = None
) -> str:
    """Generates a short-lived JWT access token."""
    now = datetime.datetime.now(datetime.timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + datetime.timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    payload: Dict[str, Any] = {
        "sub": str(subject),
        "role": role,
        "iat": now,
        "exp": expire,
        "iss": "securevault-atm",
        "aud": "securevault-api"
    }
    if extra_claims:
        payload.update(extra_claims)
    
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodes and validates a JWT token."""
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            issuer="securevault-atm",
            audience="securevault-api"
        )
        return payload
    except jwt.PyJWTError:
        return None


def constant_time_compare(val1: str, val2: str) -> bool:
    """Compares two strings in constant time to prevent timing attacks."""
    return hmac.compare_digest(val1.encode(), val2.encode())
