from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Dict
from datetime import datetime
from bson import ObjectId

from database import get_collection
from auth import require_admin
from models import AdminVerifyRequest

router = APIRouter(prefix="/api")

@router.put("/incidents/{id}/verify")
async def verify_incident(id: str, req: AdminVerifyRequest, admin: dict = Depends(require_admin)):
    if req.status not in ["verified", "false_positive", "under_review", "pending"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Forbidden: Invalid target status action selected."
        )
        
    inc_coll = get_collection("incidents")
    try:
        inc = await inc_coll.find_one({"_id": id})
        if not inc:
            inc = await inc_coll.find_one({"_id": ObjectId(id)})
    except Exception:
        inc = await inc_coll.find_one({"_id": id})
        
    if not inc:
        raise HTTPException(status_code=404, detail="Incident targeted document not found.")
        
    update_payload = {
        "status": req.status,
        "admin_notes": req.admin_notes or "",
        "updated_at": datetime.utcnow().isoformat(),
        "verified_at": datetime.utcnow().isoformat(),
        "verified_by": str(admin["_id"])
    }
    
    await inc_coll.update_one({"_id": inc["_id"]}, {"$set": update_payload})
    
    # Log in audit trace logs
    audit_coll = get_collection("audit_logs")
    await audit_coll.insert_one({
        "actor_id": str(admin["_id"]),
        "action": f"DECIDE_{req.status.upper()}",
        "target_id": str(inc["_id"]),
        "details": f"Admin verified incident '{inc.get('title')}' status to: {req.status}",
        "timestamp": datetime.utcnow().isoformat()
    })
    
    return {"message": "Incident review modified successfully.", "id": str(inc["_id"]), "status": req.status}

@router.get("/stats/platform")
async def get_platform_analytics(admin: dict = Depends(require_admin)):
    inc_coll = get_collection("incidents")
    users_coll = get_collection("users")
    comments_coll = get_collection("comments")
    audit_coll = get_collection("audit_logs")
    
    total_incidents = await inc_coll.count_documents()
    verified_incidents = await inc_coll.count_documents({"status": "verified"})
    pending_incidents = await inc_coll.count_documents({"status": "pending"})
    false_positives = await inc_coll.count_documents({"status": "false_positive"})
    
    total_users = await users_coll.count_documents()
    total_comments = await comments_coll.count_documents()
    
    # Severity counters
    critical_count = await inc_coll.count_documents({"severity": "Critical"})
    high_count = await inc_coll.count_documents({"severity": "High"})
    medium_count = await inc_coll.count_documents({"severity": "Medium"})
    low_count = await inc_coll.count_documents({"severity": "Low"})
    
    # Type counters
    phishing_count = await inc_coll.count_documents({"incident_type": "phishing"})
    malware_count = await inc_coll.count_documents({"incident_type": "malware"})
    ip_count = await inc_coll.count_documents({"incident_type": "suspicious_ip"})
    url_count = await inc_coll.count_documents({"incident_type": "suspicious_url"})
    other_count = await inc_coll.count_documents({"incident_type": "other"})
    
    # Fetch recent audit logs for administration timeline
    audit_cursor = await audit_coll.find()
    all_audits = await audit_cursor.to_array()
    
    sanitized_audits = []
    for aud in all_audits[-15:]: # Get last 15 actions
        sanitized_audits.append({
            "id": str(aud.get("_id")),
            "actor_id": aud.get("actor_id"),
            "action": aud.get("action"),
            "target_id": aud.get("target_id"),
            "details": aud.get("details"),
            "timestamp": aud.get("timestamp")
        })
    try:
        sanitized_audits.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    except Exception:
        pass
        
    return {
        "summary": {
            "total_incidents": total_incidents,
            "verified_incidents": verified_incidents,
            "pending_incidents": pending_incidents,
            "false_positives": false_positives,
            "verification_rate": round((verified_incidents / total_incidents * 100), 1) if total_incidents > 0 else 0.0,
            "total_users": total_users,
            "total_comments": total_comments
        },
        "severity": {
            "Critical": critical_count,
            "High": high_count,
            "Medium": medium_count,
            "Low": low_count
        },
        "types": {
            "phishing": phishing_count,
            "malware": malware_count,
            "suspicious_ip": ip_count,
            "suspicious_url": url_count,
            "other": other_count
        },
        "recent_audit_trail": sanitized_audits
    }
