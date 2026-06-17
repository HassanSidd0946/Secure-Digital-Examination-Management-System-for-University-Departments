from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from auth_service import create_access_token, hash_password, verify_password
from crypto_service import generate_rsa_keys 
from database import get_db
from models import User, UserRole

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Dummy hash used to keep login timing constant when username is not found
_DUMMY_HASH, _DUMMY_SALT = hash_password("__dummy__")

# Simple in-memory rate limiter for failed logins (IP-based)
# Structure: { ip_address: [timestamp1, timestamp2, ...] }
_failed_logins: dict[str, list[float]] = defaultdict(list)
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_WINDOW_SECONDS = 60


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)
    department: str = Field(min_length=2, max_length=100)
    role: UserRole

    @field_validator("department")
    @classmethod
    def normalize_department(cls, v: str) -> str:
        # Standardize input (e.g., "computer science" -> "COMPUTER SCIENCE")
        return v.strip().upper()

    @field_validator("username")
    @classmethod
    def normalize_username(cls, v: str) -> str:
        v = v.strip()  # Normalize whitespace
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Username may only contain letters, digits, hyphens, and underscores.")
        return v.lower()

    @field_validator("password")
    @classmethod
    def validate_password_complexity(cls, v: str) -> str:
        if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$", v):
            raise ValueError("Password must contain at least one uppercase letter, one lowercase letter, and one number.")
        return v


class UserLogin(BaseModel):
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=128)


class RegisterResponse(BaseModel):
    message: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    role: UserRole


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
def register_user(payload: UserCreate, db: Session = Depends(get_db)):
    """Register a new user with a salted password hash and RSA key pair."""
    
    # Pre-check for duplicate username
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already registered.")

    # Check 2: Strict Department Guardrail
    if payload.role == UserRole.HOD:
        # Check if an HOD already exists for this exact department
        existing_hod = db.query(User).filter(
            User.role == UserRole.HOD,
            User.department == payload.department
        ).first()
        
        if existing_hod:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, 
                f"Registration Denied: The {payload.department} department already has an assigned HOD."
            )

    pw_hash, salt = hash_password(payload.password)
    
    # Generate RSA keys for the user's envelope encryption
    try:
        private_pem, public_pem = generate_rsa_keys()
    except Exception as exc:
        logger.error("rsa-key-generation-failed", exc_info=exc)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Failed to generate security keys.")

    # Attach the keys to the User model
    user = User(
        username=payload.username, 
        password_hash=pw_hash, 
        salt_hex=salt, 
        role=payload.role,
        department=payload.department,
        public_key_pem=public_pem,
        private_key_pem=private_pem
    )

    try:
        db.add(user)
        db.commit()
        db.refresh(user)
        logger.info("user-registered", extra={"username_len": len(payload.username), "role": payload.role})
        
        return RegisterResponse(
            message="User registered successfully."
        )
    except IntegrityError:
        db.rollback()
        logger.warning("registration-integrity-error")
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already registered.")

@router.post("/login", response_model=TokenResponse)
def login_user(request: Request, payload: UserLogin, db: Session = Depends(get_db)):
    """Authenticate a user and return a signed JWT."""
    client_ip = request.client.host if request.client else "unknown"
    current_time = time.time()

    # Clean up old failed attempts outside the lockout window for this IP
    _failed_logins[client_ip] = [
        t for t in _failed_logins[client_ip] 
        if current_time - t < LOCKOUT_WINDOW_SECONDS
    ]

    # Rate Limit Enforcement
    if len(_failed_logins[client_ip]) >= MAX_FAILED_ATTEMPTS:
        logger.warning("login-rate-limited", extra={"ip": client_ip})
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed login attempts. Try again later.")

    user = db.query(User).filter(User.username == payload.username).first()

    # Always run verify_password to keep timing constant
    reference_hash = user.password_hash if user else _DUMMY_HASH
    reference_salt = user.salt_hex      if user else _DUMMY_SALT
    valid = verify_password(payload.password, reference_hash, reference_salt)

    if not user or not valid:
        # Record the failed attempt
        _failed_logins[client_ip].append(current_time)
        logger.warning("login-failed", extra={"username_len": len(payload.username), "ip": client_ip})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password.")

    # Audit successful login
    logger.info("login-success", extra={"ref": user.id, "ip": client_ip})

    token = create_access_token(data={"sub": str(user.id), "role": user.role})
    return TokenResponse(access_token=token, token_type="bearer", role=user.role)

@router.get("/directory", response_model=list[dict])
def get_user_directory(db: Session = Depends(get_db)):
    """Returns a list of all system users to populate UI selectors securely."""
    users = db.query(User.id, User.username, User.role, User.department).all()
    return [
        {
            "id": u.id, 
            "username": u.username, 
            "role": u.role.upper(), 
            "department": u.department
        } 
        for u in users
    ]
