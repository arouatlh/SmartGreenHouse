"""
AUTH ROUTER
-----------
Handles:
- Login (issue access + refresh tokens)
- Refresh (rotate refresh token)
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from datetime import datetime, timezone

from app.services.firebase_service import db
from app.services.auth_service import (
    verify_password,
    create_access_token,
    create_refresh_token,
    rotate_refresh_token,
)
from app.utils.rbac import get_current_user

router = APIRouter()


class LoginRequest(BaseModel):
    email: str
    password: str
    device: str = "Browser"


class RefreshRequest(BaseModel):
    refresh_token: str
    device: str = "Browser"


@router.post("/login")
def login(data: LoginRequest):
    # Find user by email
    query = (
        db.collection("users")
        .where("email", "==", data.email.strip())
        .limit(1)
        .stream()
    )

    doc = next(query, None)
    if not doc:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user_id = doc.id
    user = doc.to_dict() or {}

    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="User disabled")

    # SAFE: use get() so missing field won't crash
    if not verify_password(data.password, user.get("password_hash")):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Update last login timestamp (timezone-aware)
    db.collection("users").document(user_id).set(
        {"last_login_at": datetime.now(timezone.utc)},
        merge=True,
    )

    access_token = create_access_token(user_id=user_id, role=user.get("role", "user"))
    refresh_token = create_refresh_token(user_id=user_id, device=data.device)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/refresh")
def refresh(data: RefreshRequest):
    try:
        new_access, new_refresh = rotate_refresh_token(
            old_refresh_token=data.refresh_token,
            device=data.device,
        )
        return {
            "access_token": new_access,
            "refresh_token": new_refresh,
            "token_type": "bearer",
        }
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))


@router.get("/me")
def me(user: dict = Depends(get_current_user)):
    return {"status": "success", "data": user}