from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import sensor, control, alerts, auth, users
from app.routers import nutrients, growth
from app.routers import settings, devices

app = FastAPI(title="Greenhouse IoT System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(users.router, prefix="/api/users", tags=["User Management"])
app.include_router(sensor.router, prefix="/api/sensor", tags=["Monitoring"])
app.include_router(control.router, prefix="/api/control", tags=["Actions"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["Notifications"])
app.include_router(nutrients.router, prefix="/api/nutrients", tags=["Nutrients"])
app.include_router(growth.router, prefix="/api/growth", tags=["Growth"])
app.include_router(settings.router, prefix="/api/settings", tags=["Settings"])
app.include_router(devices.router, prefix="/api/devices", tags=["Devices"])

@app.get("/")
def home():
    return {"message": "Greenhouse Backend is running!"}