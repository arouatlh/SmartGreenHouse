"""
USERS ROUTER
------------
Handles user management.
Only Admin can:
- Create users
- List users
- Deactivate users
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from datetime import datetime
from datetime import timezone
from app.services.firebase_service import db
from app.services.auth_service import hash_password
from app.utils.rbac import require_admin
from app.utils.rbac import get_current_user
from app.models import Role

router = APIRouter()


# -----------------------------
# REQUEST MODELS
# -----------------------------

class CreateUserRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: Role = Role.user


# -----------------------------
# CREATE USER (Admin Only)
# -----------------------------

# @router.post("/", dependencies=[Depends(require_admin)])
@router.post("/")
def create_user(data: CreateUserRequest):
    """
    Creates a new user with hashed password.
    """

    # Ensure username is unique
    existing = db.collection("users") \
        .where("username", "==", data.username) \
        .limit(1) \
        .stream()

    if next(existing, None):
        raise HTTPException(status_code=409, detail="Username already exists")

    doc_ref = db.collection("users").document()

    doc_ref.set({
        "username": data.username,
        "email": data.email,
        "password_hash": hash_password(data.password),
        "role": data.role.value,
        "is_active": True,
        "created_at": datetime.utcnow(),
        "last_login_at": None
    })

    return {
        "status": "success",
        "user_id": doc_ref.id
    }


# -----------------------------
# LIST USERS (Admin Only)
# -----------------------------

@router.get("/", dependencies=[Depends(require_admin)])
def list_users():
    """
    Returns all users (excluding password hashes).
    """

    docs = db.collection("users").stream()
    users = []

    for doc in docs:
        data = doc.to_dict()
        data["id"] = doc.id

        # Never expose password hash
        data.pop("password_hash", None)

        users.append(data)

    return {
        "status": "success",
        "data": users
    }



# -----------------------------
# DEACTIVATE USER
# -----------------------------
@router.put("/{user_id}/deactivate", dependencies=[Depends(require_admin)])
def deactivate_user(user_id: str, current_user: dict = Depends(get_current_user)):

    # Prevent self-deactivation
    if current_user.get("sub") == user_id:
        raise HTTPException(status_code=400, detail="You cannot deactivate yourself")

    ref = db.collection("users").document(user_id)
    doc = ref.get()

    if not doc.exists:
        raise HTTPException(status_code=404, detail="User not found")

    ref.set({
        "is_active": False,
        "deactivated_at": datetime.now(timezone.utc)
    }, merge=True)

    return {"status": "success", "message": "User deactivated"}


# -----------------------------
# REACTIVATE USER
# -----------------------------
@router.put("/{user_id}/reactivate", dependencies=[Depends(require_admin)])
def reactivate_user(user_id: str):

    ref = db.collection("users").document(user_id)
    doc = ref.get()

    if not doc.exists:
        raise HTTPException(status_code=404, detail="User not found")

    ref.set({
        "is_active": True,
        "deactivated_at": None
    }, merge=True)

    return {"status": "success", "message": "User reactivated"}