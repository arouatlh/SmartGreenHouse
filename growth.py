# FILE: app/routers/growth.py
"""
growth.py
---------
Handles Growth Phase Timeline.

Endpoints:
- GET /history?range=.. -> Admin + User (timeline list)

The write happens automatically when mode changes in control.py (we will update control.py next).
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from datetime import datetime, timedelta, timezone
from firebase_admin import firestore

from app.services.firebase_service import db
from app.utils.rbac import require_user_or_admin

router = APIRouter()


def _range_to_start_time(range: str) -> datetime:
    now = datetime.now(timezone.utc)
    if range == "24h":
        return now - timedelta(hours=24)
    if range == "7d":
        return now - timedelta(days=7)
    return now - timedelta(days=30)


@router.get("/history", dependencies=[Depends(require_user_or_admin)])
async def get_growth_phase_history(range: str = Query("24h", enum=["24h", "7d", "30d"])):
    try:
        start_time = _range_to_start_time(range)

        query = (
            db.collection("growth_phase_history")
            .where("changed_at", ">=", start_time)
            .order_by("changed_at", direction=firestore.Query.ASCENDING)
        )

        docs = query.stream()
        rows = []

        for d in docs:
            item = d.to_dict()
            item["id"] = d.id
            rows.append(item)

        return {
            "status": "success",
            "range": range,
            "count": len(rows),
            "data": rows
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch growth history: {str(e)}")
