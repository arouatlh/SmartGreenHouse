"""
RBAC (Role-Based Access Control)
--------------------------------
This file protects routes.

Responsibilities:
- Extract JWT from request header
- Validate token
- Enforce role restrictions
"""

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.services.auth_service import decode_access_token
from app.services.firebase_service import db


# HTTPBearer automatically reads: Authorization: Bearer <token>
security = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    token = credentials.credentials

    try:
        payload = decode_access_token(token)

        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token subject")

        # 🔥 CHECK if user is still active
        doc = db.collection("users").document(user_id).get()
        if not doc.exists:
            raise HTTPException(status_code=401, detail="User not found")

        user_data = doc.to_dict()
        if not user_data.get("is_active", True):
            raise HTTPException(status_code=403, detail="User disabled")

        return payload

    except ValueError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token"
        )



def require_user_or_admin(user: dict = Depends(get_current_user)) -> dict:
    """
    Allows both admin and user roles.
    """
    if user.get("role") not in ["admin", "user"]:
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )
    return user


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    """
    Allows only admin role.
    """
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin role required"
        )
    return user
