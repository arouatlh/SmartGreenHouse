# FILE: alert_service.py
# This is the "Safety Monitor" of the greenhouse.
# While sensors just report data, this service actually "thinks" about that data.
# It compares live readings against the goals set by the user in the config.
# If something is wrong (like the water being too acidic), it automatically
# creates an entry in the 'alerts' collection for the UI to display.

from app.services.firebase_service import db
from app.models import Alert
from datetime import datetime

async def check_sensor_thresholds(sensor_data: dict):
    """
    Compares incoming sensor readings against the configured greenhouse
    thresholds and generates alerts when violations are detected.
    """

    # Fetch system configuration (targets and thresholds)
    config_ref = db.collection("controls").document("system_config").get()
    if not config_ref.exists:
        return

    config = config_ref.to_dict()
    triggered_alerts = []

    # --- pH check ---
    current_ph = sensor_data.get("ph")
    target_ph = config.get("target_ph", 6.0)
    if current_ph is not None and abs(current_ph - target_ph) > 0.5:
        triggered_alerts.append(Alert(
            sensor_type="pH",
            measured_value=current_ph,
            exceeded_threshold=f"Goal: {target_ph} +/- 0.5",
            timestamp=datetime.now(),
            status="Active"
        ))

    # --- EC check ---
    current_ec = sensor_data.get("ec")
    target_ec = config.get("target_ec", 1.8)
    if current_ec is not None and abs(current_ec - target_ec) > 0.4:
        triggered_alerts.append(Alert(
            sensor_type="EC",
            measured_value=current_ec,
            exceeded_threshold=f"Goal: {target_ec} +/- 0.4",
            timestamp=datetime.now(),
            status="Active"
        ))

    # --- Water temperature check ---
    current_temp = sensor_data.get("water_temp")
    max_temp = config.get("threshold_temp", 28.0)
    if current_temp is not None and current_temp > max_temp:
        triggered_alerts.append(Alert(
            sensor_type="Water Temp",
            measured_value=current_temp,
            exceeded_threshold=f"Max: {max_temp}°C",
            timestamp=datetime.now(),
            status="Active"
        ))

    # Persist triggered alerts
    for alert in triggered_alerts:
        db.collection("alerts").add(alert.dict())
