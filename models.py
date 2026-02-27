# FILE: models.py
# This is our "Data Rulebook." 
# It defines exactly what information we allow into our system.
# If the IoT sensors or UI try to send data that doesn't match these 
# rules (like a word instead of a number for pH), the backend will 
# block it to prevent the database from breaking.

from pydantic import BaseModel
from datetime import datetime
from typing import Optional
from enum import Enum

# -----------------------------
# USER ROLE ENUM
# -----------------------------
class Role(str, Enum):
    admin = "admin"
    user = "user"


# 1. THE SENSOR RULE: 
# This checks data coming from the environment (pH, EC, etc.).
# It ensures they are all numbers (floats).
class SensorReading(BaseModel):
    ph: float
    ec: float
    water_temp: float
    air_temp: float
    humidity: float
    flow_rate: float
    light_intensity: float
    timestamp: Optional[datetime] = None

# 2. THE DEVICE RULE: 
# This handles turning hardware ON (True) or OFF (False).
class ControlState(BaseModel):
    device_id: str
    status: bool  
    last_updated: Optional[datetime] = None

# 3. THE CONFIGURATION RULE: 
# This saves the "Goals" for the plants (Modes and Targets).
class ModeUpdate(BaseModel):
    mode: str
    target_ph: float
    target_ec: float

    # ✅ NEW: Grow light settings
    light_intensity: Optional[int] = None   # 0–100
    light_on_time: Optional[str] = None     # "06:00"
    light_off_time: Optional[str] = None    # "22:00"


# 4. THE ALERT RULE: 
# This handles the "Emergency Notifications."
# If a sensor value goes outside the safe range (like pH being too high), 
# this rule ensures the incident is recorded so the UI can notify the user.
class Alert(BaseModel):
    sensor_type: str        # Which sensor triggered it (e.g., "pH", "EC", "Air Temp")
    measured_value: float   # The actual "dangerous" number detected
    exceeded_threshold: str # The limit that was broken (e.g., "> 6.5")
    timestamp: datetime = datetime.now() # Exactly when it happened
    status: str = "Active"  # Whether the user has seen/fixed it ("Active" or "Dismissed")
