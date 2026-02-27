# app/routers/devices.py
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from datetime import datetime, timezone
from app.services.firebase_service import db
from app.utils.rbac import require_user_or_admin, require_admin

router = APIRouter()


class PairRequest(BaseModel):
    pair_code: str


class DeviceUpdate(BaseModel):
    name: str | None = None
    location: str | None = None


def _get_user_id(user: dict) -> str:
    # Most JWT libraries store principal in "sub"
    user_id = user.get("sub") or user.get("user_id") or user.get("uid")
    if not user_id:
        raise HTTPException(status_code=401, detail="Token missing subject (sub/user_id/uid)")
    return str(user_id)


def _get_user_email_from_users_collection(user_id: str) -> str | None:
    # Optional: store owner_email for easier debugging / UI display
    doc = db.collection("users").document(user_id).get()
    if not doc.exists:
        return None
    data = doc.to_dict() or {}
    return data.get("email")


@router.get("/")
async def list_devices(user: dict = Depends(require_user_or_admin)):
    """
    - admin: sees all devices
    - user: sees only devices they own (owner_id == user_id)
    """
    try:
        role = user.get("role")
        user_id = _get_user_id(user)

        if role == "admin":
            docs = db.collection("devices").stream()
        else:
            docs = db.collection("devices").where("owner_id", "==", user_id).stream()

        data = []
        for d in docs:
            row = d.to_dict() or {}
            row["id"] = d.id
            data.append(row)

        return {"status": "success", "data": data}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/pair")
async def pair_device(body: PairRequest, user: dict = Depends(require_user_or_admin)):
    """
    Secure Pair flow:
    - Find device by pair_code
    - If paired and owned by someone else -> block (409)
    - Else set paired=True + owner_id (+ owner_email optional) + paired_at
    """
    try:
        user_id = _get_user_id(user)

        q = (
            db.collection("devices")
            .where("pair_code", "==", body.pair_code)
            .limit(1)
            .stream()
        )
        doc = next(q, None)
        if not doc:
            raise HTTPException(status_code=404, detail="Invalid pair code")

        device_data = doc.to_dict() or {}
        already_paired = bool(device_data.get("paired"))
        owner_id = device_data.get("owner_id")

        # paired to someone else
        if already_paired and owner_id and owner_id != user_id:
            raise HTTPException(status_code=409, detail="Device already paired to another user")

        owner_email = _get_user_email_from_users_collection(user_id)

        db.collection("devices").document(doc.id).set(
            {
                "paired": True,
                "owner_id": user_id,
                "owner_email": owner_email,  # optional, can be None
                "paired_at": datetime.now(timezone.utc),
                "last_seen_at": datetime.now(timezone.utc),
            },
            merge=True,
        )

        return {"status": "success", "message": "Device paired", "device_id": doc.id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{device_id}")
async def update_device(device_id: str, body: DeviceUpdate, user: dict = Depends(require_admin)):
    try:
        db.collection("devices").document(device_id).set(
            {
                **{k: v for k, v in body.model_dump().items() if v is not None},
                "updated_at": datetime.now(timezone.utc),
            },
            merge=True,
        )
        return {"status": "success", "message": "Device updated"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{device_id}")
async def delete_device(device_id: str, user: dict = Depends(require_admin)):
    try:
        db.collection("devices").document(device_id).delete()
        return {"status": "success", "message": "Device removed"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
