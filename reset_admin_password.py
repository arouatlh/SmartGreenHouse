from app.services.firebase_service import db
from app.services.auth_service import hash_password
from datetime import datetime, timezone

email = "admin@smartgreenhouse.com"
new_password = "Admin12345!"

print("PW bytes:", len(new_password.encode("utf-8")))  # should be small

docs = list(db.collection("users").where("email", "==", email).limit(1).stream())
if not docs:
    raise Exception("User not found")

doc = docs[0]
new_hash = hash_password(new_password)

db.collection("users").document(doc.id).set({
    "password_hash": new_hash,
    "updated_at": datetime.now(timezone.utc),
}, merge=True)

print("✅ Password reset OK for:", email)
print("✅ Hash prefix:", new_hash[:4])  # should start with $2b$ or $2a$