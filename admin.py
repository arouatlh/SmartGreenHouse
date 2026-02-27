from app.services.firebase_service import db
from app.services.auth_service import hash_password
from datetime import datetime, timezone

email = "admin@smartgreenhouse.com"
new_password = "Admin12345!"

docs = list(db.collection("users").where("email", "==", email).limit(1).stream())
if not docs:
    raise Exception("User not found")

doc = docs[0]
db.collection("users").document(doc.id).set({
    "password_hash": hash_password(new_password),
    "updated_at": datetime.now(timezone.utc),
}, merge=True)

print("✅ Password reset OK for:", email)