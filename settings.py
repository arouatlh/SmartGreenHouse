# app/routers/settings.py
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from datetime import datetime, timezone

from app.services.firebase_service import db
from app.utils.rbac import require_user_or_admin

router = APIRouter()

# ✅ Minimal preference model (expand later)
class AlertPreferences(BaseModel):
    email_enabled: bool = True
    push_enabled: bool = False
    ph_alert: bool = True
    ec_alert: bool = True
    temp_alert: bool = True
    humidity_alert: bool = True

def _get_user_email_from_request(request):
    """
    ✅ IMPORTANT:
    Your RBAC probably sets request.state.user or similar.
    If not, you can temporarily send email in header/query while testing.
    """
    user = getattr(request.state, "user", None)
    if user and isinstance(user, dict) and user.get("email"):
        return user["email"]
    # fallback for testing (not ideal, but works)
    return None

@router.get("/preferences", dependencies=[Depends(require_user_or_admin)])
async def get_my_preferences():
    """
    Returns the current user's alert preferences.
    """
    try:
        # ✅ simplest keying strategy: 1 preferences doc per user email
        # If you don’t have request.state.user, hardcode doc id for now while testing.
        # Later we will wire current user properly.
        doc_id = "demo_user@example.com"

        doc = db.collection("user_preferences").document(doc_id).get()
        if not doc.exists:
            return {"status": "success", "data": {}}

        return {"status": "success", "data": doc.to_dict()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/preferences", dependencies=[Depends(require_user_or_admin)])
async def update_my_preferences(prefs: AlertPreferences):
    """
    Saves the current user's alert preferences.
    """
    try:
        doc_id = "demo_user@example.com"

        db.collection("user_preferences").document(doc_id).set({
            **prefs.model_dump(),
            "updated_at": datetime.now(timezone.utc)
        }, merge=True)

        return {"status": "success", "message": "Preferences saved"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
