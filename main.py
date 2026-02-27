# FILE: main.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Import ALL routers
from app.routers import sensor, control, alerts, auth, users
from app.routers import nutrients, growth
from app.routers import settings, devices

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://YOUR-FIREBASE-PROJECT.web.app",
        "https://YOUR-FIREBASE-PROJECT.firebaseapp.com",
        # add custom domain if you have one
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# then your routers
# app.include_router(...)




# Initialize FastAPI app
app = FastAPI(title="Greenhouse IoT System")

# CORS configuration
from fastapi.middleware.cors import CORSMiddleware

# ---- app.add_middleware(
#    CORSMiddleware,
    #   allow_origins=[
    #    "http://localhost:5173",
    #    "http://127.0.0.1:5173",
    #    "https://studio-4948649727-6e3c2.web.app",
    # ],
    # allow_credentials=True,
    # allow_methods=["*"],
    # allow_headers=["*"],
#)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# ROUTERS REGISTRATION
# -----------------------------

# Authentication
app.include_router(
    auth.router,
    prefix="/api/auth",
    tags=["Authentication"]
)

# User Management (Admin only)
app.include_router(
    users.router,
    prefix="/api/users",
    tags=["User Management"]
)

# Monitoring
app.include_router(
    sensor.router,
    prefix="/api/sensor",
    tags=["Monitoring"]
)

# Device Control & Configuration
app.include_router(
    control.router,
    prefix="/api/control",
    tags=["Actions"]
)

# Alerts
app.include_router(
    alerts.router,
    prefix="/api/alerts",
    tags=["Notifications"]
)

app.include_router(nutrients.router, prefix="/api/nutrients", tags=["Nutrients"])
app.include_router(growth.router, prefix="/api/growth", tags=["Growth"])
app.include_router(settings.router, prefix="/api/settings", tags=["Settings"])
app.include_router(devices.router, prefix="/api/devices", tags=["Devices"])

# -----------------------------
# Health Check
# -----------------------------
@app.get("/")
def home():
    return {"message": "Greenhouse Backend is running!"}

