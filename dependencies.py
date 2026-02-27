"""
dependencies.py
--------------
This file defines reusable FastAPI dependencies.

Why do we need this file?
- To avoid repeating token-checking logic in every router file.
- To enforce security (JWT authentication) consistently across the system.

What it does:
- Reads the JWT access token from the request header:
    Authorization: Bearer <token>
- Validates the token (signature + expiry) using decode_access_token()
- Returns the decoded payload (e.g., user_id + role) for use inside routes
- If token is missing/invalid/expired → raises HTTP 401
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Your existing JWT validator from auth_service.py
from app.services.auth_service import decode_access_token

# HTTPBearer tells FastAPI to expect:
# Authorization: Bearer <token>
# If missing, FastAPI will raise 403 by default ("Not authenticated")
security = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """
    Dependency: Get current authenticated user from JWT.

    FastAPI will automatically:
    1) Look for Authorization header
    2) Ensure it has Bearer token format
    3) Put it inside `credentials.credentials`

    Returns:
    - Decoded JWT payload dict, example:
      {
        "sub": "<user_id>",
        "role": "admin",
        "iat": 1234567890,
        "exp": 1234569999
      }

    Raises:
    - 401 if token is invalid/expired
    """

    # Extract the raw token string
    token = credentials.credentials

    # Validate + decode JWT
    # Your decode_access_token() raises ValueError if invalid/expired
    try:
        payload = decode_access_token(token)
        return payload

    except ValueError:
        # We return 401 because:
        # - Token is invalid or expired
        # - Client should re-login or refresh token
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token"
        )


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    """
    Dependency: Require admin role.

    Use this if you want some endpoints to be admin-only.
    Example usage:
        @router.post("/something")
        def something(user=Depends(require_admin)):
            ...

    Raises:
    - 403 if user is not admin
    """

    if user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required"
        )

    return user
