# FILE: alerts.py
# RBAC Policy:
# - View Alerts → Admin + User

from fastapi import APIRouter, HTTPException, Depends
from app.services.firebase_service import db
from app.utils.rbac import require_user_or_admin
from firebase_admin import firestore

router = APIRouter()


@router.get("/", dependencies=[Depends(require_user_or_admin)])
async def get_all_alerts():
    try:
        query = db.collection("alerts") \
            .order_by("timestamp", direction=firestore.Query.DESCENDING) \
            .limit(20)

        docs = query.stream()

        alerts_list = []
        for doc in docs:
            data = doc.to_dict()
            data['id'] = doc.id
            alerts_list.append(data)

        return {"status": "success", "data": alerts_list}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
