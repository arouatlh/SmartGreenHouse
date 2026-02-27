# FILE: firebase_service.py
import os
import json
import firebase_admin
from firebase_admin import credentials, firestore
from dotenv import load_dotenv

load_dotenv()

def initialize_firebase():
    if firebase_admin._apps:
        return

    # 🔹 Option 1: Railway Environment Variable (Production)
    firebase_json = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON")

    if firebase_json:
        cred_dict = json.loads(firebase_json)
        cred = credentials.Certificate(cred_dict)
        firebase_admin.initialize_app(cred)
        return

    # 🔹 Option 2: Local Development (fallback)
    firebase_key_path = os.getenv("FIREBASE_KEY_PATH", "serviceAccountKey.json")
    cred = credentials.Certificate(firebase_key_path)
    firebase_admin.initialize_app(cred)

initialize_firebase()

db = firestore.client()
