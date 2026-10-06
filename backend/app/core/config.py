import os
import json
from pathlib import Path
from typing import List, Union
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
_DEFAULT_DB_FILE = (_BASE_DIR / "securevault.db").resolve().as_posix()


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    PROJECT_NAME: str = "SecureVault ATM"
    API_V1_STR: str = "/api/v1"

    # Security & Tokens
    SECRET_KEY: str = "super_secure_vault_atm_secret_key_minimum_32_chars_long_12345"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    IDLE_SESSION_TIMEOUT_SECONDS: int = 600

    # Cryptography
    # 32 url-safe base64-encoded bytes for Fernet
    FERNET_KEY: str = "bGFyZ2VzZWNyZXRrZXlmb3JmZXJuZXQxMjM0NTY3ODkwMTI="
    PIN_PEPPER: str = "securevault_pin_pepper_super_secret_dev_key"

    # Database
    DATABASE_URL: str = f"sqlite+aiosqlite:///{_DEFAULT_DB_FILE}"
    MYSQL_DATABASE_URL: str = "mysql+aiomysql://root:securevault_pwd@localhost:3306/securevault_atm"
    TEST_DATABASE_URL: str = "sqlite+aiosqlite:///:memory:"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # MongoDB (Local MongoDB Compass)
    MONGODB_URL: str = "mongodb://localhost:27017"
    MONGODB_DB_NAME: str = "securevault_db"
    ENABLE_MONGODB_SYNC: bool = True

    # CORS
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://localhost:8000",
    ]

    # Audit Trail Genesis Hash (64 hex characters)
    AUDIT_GENESIS_HASH: str = "0" * 64

    # SIEM Export Path
    SIEM_EXPORT_PATH: str = "logs/siem_export.jsonl"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def async_database_url(self) -> str:
        # Check if DATABASE_URL is set in environment or default
        env_url = os.getenv("DATABASE_URL", self.DATABASE_URL)
        return env_url


settings = Settings()
