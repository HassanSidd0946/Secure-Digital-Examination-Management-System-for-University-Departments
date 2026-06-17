

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError

from config import settings

logger = logging.getLogger(__name__)

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError

    # Initialize Argon2 with configurable parameters
    _ph = PasswordHasher(
        time_cost=settings.ARGON2_TIME_COST,
        memory_cost=settings.ARGON2_MEMORY_COST,
        parallelism=settings.ARGON2_PARALLELISM,
        hash_len=16,
        salt_len=16,
    )
    _ARGON2_AVAILABLE = True
except ImportError:
    import hashlib

    _ARGON2_AVAILABLE = False


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------


class AuthException(Exception):
    """
    Raised when authentication or token validation fails.

    Unified exception type for auth layer error handling.
    """

    pass


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------


def hash_password(password: str) -> tuple[str, str]:
    """
    Hash *password* and return ``(hash, salt)``.

    * **Argon2id** is used when ``argon2-cffi`` is installed (recommended).
      The salt is embedded in the hash string; the second element of the
      tuple is an empty string kept for API compatibility.
    * Falls back to salted SHA-256 when argon2-cffi is absent.

    Args:
        password: Plain-text password to hash.

    Returns:
        Tuple of (hash_string, salt_hex). For Argon2, salt_hex is "".
    """
    if _ARGON2_AVAILABLE:
        return _ph.hash(password), ""  # salt embedded in Argon2 hash
    # SHA-256 fallback
    salt = secrets.token_hex(16)
    digest = hashlib.sha256((password + salt).encode()).hexdigest()
    return digest, salt


def verify_password(plain: str, stored_hash: str, salt: str = "") -> bool:
    """
    Return ``True`` if *plain* matches *stored_hash*.

    Constant-time comparison is guaranteed by both argon2-cffi's PasswordHasher
    and secrets.compare_digest, neutralising timing-based side-channels.

    Args:
        plain: Plain-text password to verify.
        stored_hash: Previously hashed password (from database).
        salt: Salt used during hashing (only needed for SHA-256 fallback).

    Returns:
        True if password matches, False otherwise.
    """
    if _ARGON2_AVAILABLE:
        try:
            return _ph.verify(stored_hash, plain)
        except VerifyMismatchError:
            return False
    # SHA-256 fallback with constant-time comparison
    candidate = hashlib.sha256((plain + salt).encode()).hexdigest()
    return secrets.compare_digest(candidate, stored_hash)


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------


@dataclass
class TokenData:
    """Typed payload extracted from a validated JWT."""

    sub: str  # subject (user ID)
    role: Optional[str] = None
    exp: Optional[int] = None  # Unix timestamp (int, not datetime)
    iat: Optional[int] = None  # Unix timestamp (int, not datetime)


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Encode *data* as a signed JWT access token.

    ✅ Converts datetime claims to Unix timestamps (int) for strict serializability.

    Args:
        data: Arbitrary claims; ``sub`` should identify the user (e.g., username or UUID).
        expires_delta: Override the default TTL from ``settings.ACCESS_TOKEN_EXPIRE_MINUTES``.

    Returns:
        Compact JWT string (3 dot-separated base64url segments).

    Example:
        >>> token = create_access_token({"sub": "alice", "role": "admin"})
        >>> token  # "eyJhbGc..."
    """
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta
        or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    # Convert to Unix timestamps (int) for reliable serialization
    iat_timestamp = int(now.timestamp())
    exp_timestamp = int(expire.timestamp())

    payload = {
        **data,
        "iat": iat_timestamp,  # issued at (Unix timestamp)
        "exp": exp_timestamp,  # expires at (Unix timestamp)
    }

    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> TokenData:
    """
    Validate *token* and return its claims as :class:`TokenData`.

    ✅ Validates that 'sub' claim exists before accessing it.
    ✅ Wraps JWTError into AuthException for cleaner API-layer handling.
    ✅ Preserves timestamps as int (already serialized by jwt.decode).

    Args:
        token: JWT string to decode and validate.

    Returns:
        TokenData with validated claims.

    Raises:
        AuthException: If token is malformed, signature is invalid, or required
                      claims are missing.
        ExpiredSignatureError: If token has passed its 'exp' claim (subclass of
                              AuthException for distinguishing timeout failures).

    Example:
        >>> try:
        ...     data = decode_access_token(token)
        ...     print(data.sub, data.role)
        ... except AuthException as e:
        ...     return {"error": str(e)}
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
    except ExpiredSignatureError:
        # Token is expired; re-raise as-is for distinguishing in API layer
        raise AuthException("Token has expired") from None
    except JWTError as e:
        # Malformed, invalid signature, or other JWT errors
        raise AuthException(f"Invalid token: {str(e)}") from None

    # Guard against missing 'sub' claim (control error, not KeyError)
    if "sub" not in payload:
        raise AuthException("Invalid token: missing 'sub' claim")

    return TokenData(
        sub=payload["sub"],
        role=payload.get("role"),
        exp=payload.get("exp"),  # already int from jwt.decode
        iat=payload.get("iat"),  # already int from jwt.decode
    )


__all__ = [
    "hash_password",
    "verify_password",
    "create_access_token",
    "decode_access_token",
    "TokenData",
    "AuthException",
]