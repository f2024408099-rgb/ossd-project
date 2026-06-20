import os
import asyncio
from typing import Dict, Any, List, Optional
from bson import ObjectId
from datetime import datetime

# Read MongoDB connection details from environmental configs
MONGODB_URI = os.getenv("MONGODB_URI", "")
USE_REAL_MONGO = bool(MONGODB_URI and MONGODB_URI.strip())

db_client = None
db_instance = None

if USE_REAL_MONGO:
    try:
        from motor.motor_asyncio import AsyncIOMotorClient
        db_client = AsyncIOMotorClient(MONGODB_URI)
        db_instance = db_client.get_database("cybertrace")
        print("Connected to Real MongoDB Atlas cluster.")
    except Exception as err:
        print(f"Failed to initialize real MongoDB connection: {err}. Falling back to In-Memory engine.")
        USE_REAL_MONGO = False

# --- In-Memory database structures mimicking Motor ---
_db_store: Dict[str, List[Dict[str, Any]]] = {
    "users": [],
    "incidents": [],
    "comments": [],
    "audit_logs": []
}

def match_document(doc: Dict[str, Any], query: Dict[str, Any]) -> bool:
    for key, val in query.items():
        if key == "_id":
            # Support matching both ObjectId and string translation
            doc_id = doc.get("_id")
            if isinstance(val, dict):
                # E.g., {"$ne": ref_id}
                if "$ne" in val:
                    ne_val = val["$ne"]
                    if str(doc_id) == str(ne_val):
                        return False
                    continue
            if str(doc_id) != str(val):
                return False
        elif isinstance(val, dict):
            # Complex matchers (e.g., $ne)
            doc_val = doc.get(key)
            if "$ne" in val:
                ne_val = val["$ne"]
                if str(doc_val) == str(ne_val):
                    return False
        else:
            if doc.get(key) != val:
                return False
    return True

class MockCursor:
    def __init__(self, data: List[Dict[str, Any]]):
        self.data = data

    async def to_array(self, length: Optional[int] = None) -> List[Dict[str, Any]]:
        # Return copies of dicts to prevent side-effect alterations
        return [dict(d) for d in self.data]

class MockCollection:
    def __init__(self, name: str):
        self.name = name

    async def insert_one(self, doc: Dict[str, Any]):
        if "_id" not in doc:
            doc["_id"] = ObjectId()
        _db_store[self.name].append(doc)
        return type("InsertResult", (object,), {"inserted_id": doc["_id"]})()

    async def find_one(self, query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        for doc in _db_store[self.name]:
            if match_document(doc, query):
                return dict(doc)
        return None

    async def update_one(self, query: Dict[str, Any], update: Dict[str, Any], upsert: bool = False):
        found = False
        for doc in _db_store[self.name]:
            if match_document(doc, query):
                found = True
                if "$set" in update:
                    for k, v in update["$set"].items():
                        doc[k] = v
                break
        return type("UpdateResult", (object,), {"modified_count": 1 if found else 0})()

    async def delete_one(self, query: Dict[str, Any]):
        idx_to_remove = -1
        for i, doc in enumerate(_db_store[self.name]):
            if match_document(doc, query):
                idx_to_remove = i
                break
        if idx_to_remove != -1:
            _db_store[self.name].pop(idx_to_remove)
            return type("DeleteResult", (object,), {"deleted_count": 1})()
        return type("DeleteResult", (object,), {"deleted_count": 0})()

    async def count_documents(self, query: Optional[Dict[str, Any]] = None) -> int:
        if not query:
            return len(_db_store[self.name])
        count = 0
        for doc in _db_store[self.name]:
            if match_document(doc, query):
                count += 1
        return count

    def find(self, query: Optional[Dict[str, Any]] = None) -> MockCursor:
        if not query:
            return MockCursor(_db_store[self.name])
        filtered = []
        for doc in _db_store[self.name]:
            if match_document(doc, query):
                filtered.append(doc)
        return MockCursor(filtered)


def get_collection(name: str):
    if USE_REAL_MONGO and db_instance is not None:
        return db_instance.get_collection(name)
    return MockCollection(name)


async def seed_database():
    """Seed base administrative user account and initial templates."""
    users_coll = get_collection("users")
    admin_user = await users_coll.find_one({"email": "admin@cybertrace.io"})
    
    if not admin_user:
        from auth import hash_password
        pwd_hash = hash_password("AdminSecurePassword2026")
        new_admin = {
            "email": "admin@cybertrace.io",
            "password_hash": pwd_hash,
            "display_name": "Admin Director",
            "role": "admin",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        await users_coll.insert_one(new_admin)
        print("Default admin@cybertrace.io account seeded.")

    # Seed an initial incident threat log
    incidents_coll = get_collection("incidents")
    example = await incidents_coll.find_one({"title": "Spear Phishing campaign targeting Payroll"})
    if not example:
        init_inc = {
            "reporter_id": "system",
            "reporter_email": "system@cybertrace.io",
            "reporter_name": "System Intel",
            "title": "Spear Phishing campaign targeting Payroll",
            "incident_type": "phishing",
            "severity": "High",
            "ioc_type": "domain",
            "ioc_value": "secure-payroll-authentication.com",
            "description": "Observed wave of credential harvesting phishing mails requesting validation of bank routing slips. Domain is hosting a credential replication page.",
            "evidence": ["e-mail headers captured: secure-payroll-authentication.com", "attachment: review_document.zip (hash: e2817d2)"],
            "status": "verified",
            "admin_notes": "Domain DNS blacklisted on Core Firewall routers.",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "verified_at": datetime.utcnow().isoformat(),
            "verified_by": "system"
        }
        await incidents_coll.insert_one(init_inc)
        print("Default threat incident demonstration vector seeded.")
