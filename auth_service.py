"""
AUTH SERVICE
------------
Security engine for authentication & token lifecycle.

Responsibilities:
- Hash and verify passwords (bcrypt via passlib)
- Generate access tokens (JWT, short-lived)
- Generate refresh tokens (long-lived, stored hashed in Firestore)
- Decode and validate access tokens
- Rotate refresh tokens (revoke old, issue new)
"""

import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Tuple

from jose import jwt, JWTError
from passlib.context import CryptContext
from passlib.exc import UnknownHashError
from dotenv import load_dotenv

from app.services.firebase_service import db

# Load environment variables from .env (Cloud Run should set env vars too)
load_dotenv()

# Password hashing engine (bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Load security configs from env
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "15"))
REFRESH_TOKEN_DAYS = int(os.getenv("REFRESH_TOKEN_DAYS", "14"))

# Fail fast if secret is not configured
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET is missing. Set it in your environment variables.")


# -----------------------------
# PASSWORD HANDLING
# -----------------------------

def hash_password(password: str) -> str:
    """
    Hashes a plaintext password before storing in Firestore.
    Returns a bcrypt hash string (e.g., $2b$12$...).
    """
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string")
    return pwd_context.hash(password)

    if len(password.encode("utf-8")) > 72:
        raise ValueError("Password too long for bcrypt (72 bytes max).")


def _normalize_hash_value(value: Any) -> str:
    """
    Firestore can return strings, bytes, or sometimes special types.
    We normalize to a string for passlib.
    """
    if value is None:
        return ""

    # Firestore might store bytes/blob in some cases
    if isinstance(value, (bytes, bytearray)):
        try:
            return value.decode("utf-8")
        except Exception:
            return ""

    # Some Firestore clients store blobs as objects that stringify poorly
    if not isinstance(value, str):
        try:
            value = str(value)
        except Exception:
            return ""

    return value.strip()


def verify_password(password: str, password_hash: Any) -> bool:
    """
    Verifies a plaintext password against a bcrypt hash.
    IMPORTANT: Never raise UnknownHashError to callers (prevents 500s).
    """
    if not isinstance(password, str) or not password:
        return False

    hashed = _normalize_hash_value(password_hash)
    if not hashed:
        return False

    try:
        return pwd_context.verify(password, hashed)
    except UnknownHashError:
        # Stored hash is not a valid passlib-recognized hash (bad DB data)
        return False
    except Exception:
        # Any other unexpected error should not crash auth
        return False


# -----------------------------
# ACCESS TOKEN (JWT)
# -----------------------------

def create_access_token(user_id: str, role: str) -> str:
    """
    Creates a short-lived JWT access token.
    Payload:
    - sub: user id
    - role: RBAC role
    - iat: issued at (epoch seconds)
    - exp: expiry (epoch seconds)
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_MINUTES)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """
    Validates JWT signature + expiry.
    Returns decoded payload if valid.
    Raises ValueError if invalid/expired.
    """
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError:
        raise ValueError("Invalid or expired access token")


# -----------------------------
# REFRESH TOKEN HANDLING
# -----------------------------

def _hash_refresh_token(token: str) -> str:
    """
    Hash refresh tokens before storing in DB (never store raw refresh tokens).
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_refresh_token(user_id: str, device: str = "unknown") -> str:
    """
    Generates a secure refresh token and stores its hash in Firestore.
    Returns the raw refresh token (send to client).
    """
    raw_token = secrets.token_urlsafe(48)
    token_hash = _hash_refresh_token(raw_token)

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=REFRESH_TOKEN_DAYS)

    db.collection("refresh_tokens").add({
        "user_id": user_id,
        "token_hash": token_hash,
        "created_at": now,
        "expires_at": expires_at,
        "revoked_at": None,
        "device": device,
    })

    return raw_token


def rotate_refresh_token(old_refresh_token: str, device: str = "unknown") -> Tuple[str, str]:
    """
    Refresh token rotation:
    - Validate old token hash exists
    - Reject if revoked or expired
    - Revoke old token
    - Issue new access token + new refresh token
    """
    if not old_refresh_token:
        raise ValueError("Invalid refresh token")

    token_hash = _hash_refresh_token(old_refresh_token)

    query = (
        db.collection("refresh_tokens")
        .where("token_hash", "==", token_hash)
        .limit(1)
        .stream()
    )

    doc = next(query, None)
    if not doc:
        raise ValueError("Invalid refresh token")

    data = doc.to_dict()

    if data.get("revoked_at") is not None:
        raise ValueError("Refresh token already revoked")

    now = datetime.now(timezone.utc)
    expires_at = data.get("expires_at")
    if expires_at is None:
        raise ValueError("Refresh token record corrupted (missing expires_at)")
    if now > expires_at:
        raise ValueError("Refresh token expired")

    user_id = data.get("user_id")
    if not user_id:
        raise ValueError("Refresh token record corrupted (missing user_id)")

    # Revoke old token
    db.collection("refresh_tokens").document(doc.id).set({
        "revoked_at": now
    }, merge=True)

    # Load user for role + active status
    user_doc = db.collection("users").document(user_id).get()
    if not user_doc.exists:
        raise ValueError("User not found")

    user = user_doc.to_dict() or {}
    if not user.get("is_active", True):
        raise ValueError("User disabled")

    role = user.get("role", "user")

    new_access = create_access_token(user_id=user_id, role=role)
    new_refresh = create_refresh_token(user_id=user_id, device=device)

    return new_access, new_refresh