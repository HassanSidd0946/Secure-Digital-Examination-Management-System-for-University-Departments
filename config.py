
from __future__ import annotations

import logging
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application configuration loaded from environment variables.

    Environment variables:
        DATABASE_URL: Connection string (e.g., sqlite:///app.db)
        LOG_LEVEL: Logging level for application (default: INFO)
        SQL_ECHO: Enable SQLAlchemy echo for SQL logging (default: false)
    """

    # Database
    DATABASE_URL: str = Field(
        default="sqlite:///./app.db",
        description="Database connection URL (sqlite, postgresql, mysql, etc.)",
    )

    # Logging
    LOG_LEVEL: str = Field(
        default="INFO",
        description="Application logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )

    DEBUG: bool = Field(
        default=True,
        description="Enable debug mode (show docs at /docs, /redoc; verbose logging)",
    )

    CORS_ORIGINS: list[str] = Field(
        default=["http://localhost:3000", "http://localhost:8000"],
        description="Allowed CORS origins (comma-separated if set via env)",
    )

    SQL_ECHO: bool = Field(
        default=False,
        description="Enable SQLAlchemy SQL logging (very verbose; DEBUG level only)",
    )

    # Optional: for future async settings
    DATABASE_POOL_SIZE: int = Field(
        default=5,
        description="Connection pool size (ignored by SQLite)",
    )

    DATABASE_MAX_OVERFLOW: int = Field(
        default=10,
        description="Maximum overflow connections beyond pool_size",
    )

    # Security & Authentication
    SECRET_KEY: str = Field(
        default="dev-secret-key-change-in-production",
        description="Secret key for signing JWTs; use a strong random value in production",
    )

    ALGORITHM: str = Field(
        default="HS256",
        description="JWT signing algorithm (HS256, RS256, etc.)",
    )

    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=30,
        description="JWT access token TTL in minutes",
    )

    # Argon2 password hashing parameters
    ARGON2_TIME_COST: int = Field(
        default=2,
        description="Argon2 time cost parameter (iterations)",
    )

    ARGON2_MEMORY_COST: int = Field(
        default=65536,
        description="Argon2 memory cost in KiB (65536 = 64 MiB, typical for web)",
    )

    ARGON2_PARALLELISM: int = Field(
        default=4,
        description="Argon2 parallelism factor (number of threads)",
    )

    @field_validator("SECRET_KEY", mode="before")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        """Ensure SECRET_KEY is not the insecure default in production."""
        if not v or len(v) < 32:
            import warnings

            warnings.warn(
                "SECRET_KEY is less than 32 characters or not set. "
                "This is only acceptable for development. Use a 256-bit random key in production."
            )
        return v

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        """Ensure DATABASE_URL is provided and non-empty."""
        if not v or not isinstance(v, str):
            raise ValueError("DATABASE_URL must be a non-empty string")
        return v

    @field_validator("LOG_LEVEL", mode="before")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Ensure LOG_LEVEL is a valid logging level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        level = (v or "INFO").upper()
        if level not in valid_levels:
            raise ValueError(f"LOG_LEVEL must be one of {valid_levels}, got {level}")
        return level

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# Instantiate settings at module load time; fail fast on bad configuration
settings = Settings()

# Configure logging
logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

__all__ = ["settings", "Settings"]
