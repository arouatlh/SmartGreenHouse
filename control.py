"""
control.py
----------
Handles:
- Manual device control
- System mode configuration
- Threshold configuration

RBAC Policy:
- POST   /control               → Admin + User
- PUT    /settings/mode         → Admin + User
- PUT    /settings/thresholds   → Admin only
"""

from fastapi import APIRouter, HTTPException, Depends
from datetime import datetime, timezone
from pydantic import BaseModel

from app.models import ControlState, ModeUpdate
from app.services.firebase_service import db
from app.utils.rbac import require_admin, require_user_or_admin

router = APIRouter()


# -------------------------------------------------
# Request Model for Threshold Update (typed)
# -------------------------------------------------
class ThresholdUpdate(BaseModel):
    threshold_temp: float
    ph_tolerance: float
    ec_tolerance: float


# -------------------------------------------------
# MANUAL DEVICE CONTROL
# -------------------------------------------------
@router.post("/control", dependencies=[Depends(require_user_or_admin)])
async def update_device_control(command: ControlState):
    """
    Update a specific device state (pump, light, etc.)
    """

    try:
        doc_ref = db.collection("controls").document(command.device_id)

        doc_ref.set({
            "status": command.status,
            "last_updated": datetime.now(timezone.utc)
        }, merge=True)

        return {
            "status": "success",
            "message": f"{command.device_id} is now {command.status}"
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update device control: {str(e)}"
        )


# -------------------------------------------------
# CHANGE MODE + TARGETS (Admin + User)
# -------------------------------------------------
# inside control.py (your existing file)
from datetime import datetime, timezone
from app.models import ControlState, ModeUpdate


@router.put("/settings/mode", dependencies=[Depends(require_user_or_admin)])
async def update_mode_and_targets(config: ModeUpdate):
    try:
        doc_ref = db.collection("settings").document("system_config")

        # 1) update main config
        doc_ref.set({
    "mode": config.mode,
    "target_ph": config.target_ph,
    "target_ec": config.target_ec,

    # ✅ NEW: Light settings
    "light_intensity": config.light_intensity,
    "light_on_time": config.light_on_time,
    "light_off_time": config.light_off_time,

    "updated_at": datetime.now(timezone.utc)
}, merge=True)


        # ✅ 2) NEW: log growth phase change to timeline
        db.collection("growth_phase_history").add({
            "mode": config.mode,
            "target_ph": config.target_ph,
            "target_ec": config.target_ec,
            "changed_at": datetime.now(timezone.utc)
        })

        return {"status": "success", "message": "Mode updated successfully"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update mode settings: {str(e)}")


# -------------------------------------------------
# EDIT THRESHOLDS (Admin ONLY)
# -------------------------------------------------
@router.put("/settings/thresholds", dependencies=[Depends(require_admin)])
async def update_thresholds(threshold_data: ThresholdUpdate):
    """
    Update system safety thresholds.
    Only Admin can modify.
    """

    try:
        doc_ref = db.collection("settings").document("system_config")

        doc_ref.set({
            "threshold_temp": threshold_data.threshold_temp,
            "ph_tolerance": threshold_data.ph_tolerance,
            "ec_tolerance": threshold_data.ec_tolerance,
            "updated_at": datetime.now(timezone.utc)
        }, merge=True)

        return {
            "status": "success",
            "message": "Thresholds updated successfully"
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update thresholds: {str(e)}"
        )

@router.get("/settings", dependencies=[Depends(require_user_or_admin)])
async def get_settings():
    """
    Load current system settings (mode, targets, light schedule, thresholds, etc.)
    """
    try:
        doc = db.collection("settings").document("system_config").get()
        if not doc.exists:
            return {"status": "success", "data": {}}

        return {"status": "success", "data": doc.to_dict()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/control", dependencies=[Depends(require_user_or_admin)])
async def get_all_controls():
    """
    Load latest statuses for all devices from Firestore controls collection.
    """
    try:
        docs = db.collection("controls").stream()
        data = {}
        for d in docs:
            data[d.id] = d.to_dict()
        return {"status": "success", "data": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
