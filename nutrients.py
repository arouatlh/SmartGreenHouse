# FILE: app/routers/nutrients.py
"""
nutrients.py
------------
Handles nutrient usage logging + analytics.

Endpoints:
- POST /events          -> Admin + User (log nutrient usage event manually or by automation)
- GET  /usage?range=..  -> Admin + User (return time-series + totals)

Range allowed: 24h, 7d, 30d
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from datetime import datetime, timedelta, timezone
from pydantic import BaseModel, Field
from firebase_admin import firestore

from app.services.firebase_service import db
from app.utils.rbac import require_user_or_admin

router = APIRouter()


# -----------------------------
# REQUEST MODEL
# -----------------------------
class NutrientEventCreate(BaseModel):
    # how much nutrient solution was dosed (ml)
    nutrient_ml: float = Field(..., gt=0)
    # optional: reason or type (auto/manual)
    source: str = "manual"
    timestamp: datetime | None = None


def _range_to_start_time(range: str) -> datetime:
    now = datetime.now(timezone.utc)
    if range == "24h":
        return now - timedelta(hours=24)
    if range == "7d":
        return now - timedelta(days=7)
    return now - timedelta(days=30)


# -----------------------------
# POST: log nutrient usage event
# -----------------------------
@router.post("/events", dependencies=[Depends(require_user_or_admin)])
async def create_nutrient_event(payload: NutrientEventCreate):
    try:
        ts = payload.timestamp or datetime.now(timezone.utc)

        doc = {
            "nutrient_ml": float(payload.nutrient_ml),
            "source": payload.source,
            "timestamp": ts,
        }

        ref = db.collection("nutrient_events").document()
        ref.set(doc)

        return {"status": "success", "id": ref.id, "data": doc}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create nutrient event: {str(e)}")


# -----------------------------
# GET: nutrient usage analytics
# -----------------------------
@router.get("/usage", dependencies=[Depends(require_user_or_admin)])
async def get_nutrient_usage(range: str = Query("24h", enum=["24h", "7d", "30d"])):
    try:
        start_time = _range_to_start_time(range)

        query = (
            db.collection("nutrient_events")
            .where("timestamp", ">=", start_time)
            .order_by("timestamp", direction=firestore.Query.ASCENDING)
        )

        docs = query.stream()

        events = []
        total_ml = 0.0

        for d in docs:
            item = d.to_dict()
            item["id"] = d.id

            # Firestore timestamp -> should already be datetime
            ml = float(item.get("nutrient_ml", 0.0))
            total_ml += ml

            events.append(item)

        return {
            "status": "success",
            "range": range,
            "count": len(events),
            "total_ml": round(total_ml, 2),
            "data": events,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch nutrient usage: {str(e)}")
