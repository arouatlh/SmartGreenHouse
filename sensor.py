"""
sensor.py
---------
Handles:
- Sensor data ingestion (Admin only)
- Dashboard latest reading (User + Admin)
- Historical data query (User + Admin)

RBAC Policy:
- POST /latest  → Admin only
- GET  /latest  → Admin + User
- GET  /history → Admin + User
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from datetime import datetime, timedelta, timezone
from firebase_admin import firestore

from app.models import SensorReading
from app.services.firebase_service import db
from app.services.alert_service import check_sensor_thresholds
from app.utils.rbac import require_admin, require_user_or_admin

router = APIRouter()


# -------------------------------------------------
# ADMIN ONLY — Sensor Ingestion
# -------------------------------------------------
@router.post("/latest", dependencies=[Depends(require_admin)])
async def save_sensor_data(data: SensorReading):
    """
    Save new sensor reading.
    Only Admin (or IoT device acting as admin) can call this.
    """

    try:
        # Ensure timestamp is UTC aware
        if not data.timestamp:
            data.timestamp = datetime.now(timezone.utc)

        sensor_dict = data.dict()

        # Create new document
        doc_ref = db.collection("sensors").document()
        doc_ref.set(sensor_dict)

        # Trigger alert checks asynchronously
        await check_sensor_thresholds(sensor_dict)

        return {
            "status": "success",
            "id": doc_ref.id
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to save sensor data: {str(e)}"
        )


# -------------------------------------------------
# USER + ADMIN — Latest Reading
# -------------------------------------------------
@router.get("/latest", dependencies=[Depends(require_user_or_admin)])
async def get_latest_sensor_data():
    """
    Fetch most recent sensor reading for dashboard.
    """

    try:
        query = (
            db.collection("sensors")
            .order_by("timestamp", direction=firestore.Query.DESCENDING)
            .limit(1)
        )

        docs = query.stream()

        latest_data = None
        for doc in docs:
            latest_data = doc.to_dict()
            latest_data["id"] = doc.id

        if not latest_data:
            raise HTTPException(
                status_code=404,
                detail="No sensor data found"
            )

        return {
            "status": "success",
            "data": latest_data
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch latest sensor data: {str(e)}"
        )


# -------------------------------------------------
# USER + ADMIN — Historical Data
# -------------------------------------------------
@router.get("/history", dependencies=[Depends(require_user_or_admin)])
async def get_sensor_history(
    range: str = Query("24h", enum=["24h", "7d", "30d"])
):
    """
    Fetch historical sensor readings for analytics.
    """

    try:
        now = datetime.now(timezone.utc)

        if range == "24h":
            start_time = now - timedelta(hours=24)
        elif range == "7d":
            start_time = now - timedelta(days=7)
        else:
            start_time = now - timedelta(days=30)

        query = (
            db.collection("sensors")
            .where("timestamp", ">=", start_time)
            .order_by("timestamp", direction=firestore.Query.ASCENDING)
        )

        docs = query.stream()

        history = []
        for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id
            history.append(data)

        return {
            "status": "success",
            "range": range,
            "count": len(history),
            "data": history
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch sensor history: {str(e)}"
        )
