from fastapi import APIRouter, Depends, HTTPException, status, Query
from typing import List, Optional
from datetime import datetime
from bson import ObjectId

from database import get_collection
from auth import get_current_user
from models import IncidentCreate, IncidentUpdate, CommentCreate

router = APIRouter(prefix="/api")

@router.post("/incidents")
async def create_incident(req: IncidentCreate, current_user: dict = Depends(get_current_user)):
    inc_coll = get_collection("incidents")
    
    new_inc = {
        "reporter_id": str(current_user["_id"]),
        "reporter_email": current_user["email"],
        "reporter_name": current_user.get("display_name", "Anonymous"),
        "title": req.title,
        "incident_type": req.incident_type,
        "severity": req.severity,
        "ioc_type": req.ioc_type,
        "ioc_value": req.ioc_value,
        "description": req.description,
        "evidence": req.evidence or [],
        "status": "pending",
        "admin_notes": "",
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }
    await inc_coll.insert_one(new_inc)
    
    # Audit trail
    audit_coll = get_collection("audit_logs")
    await audit_coll.insert_one({
        "actor_id": str(current_user["_id"]),
        "action": "SUBMIT_INCIDENT",
        "target_id": str(new_inc.get("_id", "")),
        "details": f"Submitted new cyber threat incident: {req.title}",
        "timestamp": datetime.utcnow().isoformat()
    })
    
    new_inc["id"] = str(new_inc.get("_id", ""))
    if "_id" in new_inc:
        del new_inc["_id"]
    return new_inc

@router.get("/incidents")
async def list_incidents(
    severity: Optional[str] = None,
    incident_type: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    inc_coll = get_collection("incidents")
    
    query = {}
    if severity:
        query["severity"] = severity
    if incident_type:
        query["incident_type"] = incident_type
    if status:
        query["status"] = status
        
    cursor = await inc_coll.find(query)
    all_inc = await cursor.to_array()
    
    sanitized = []
    for inc in all_inc:
        inc_id = str(inc.get("_id", ""))
        
        # Support optional client-side search query logic on title, ioc, or description
        if search:
            search_str = search.lower()
            if (search_str not in inc.get("title", "").lower() and
                search_str not in inc.get("ioc_value", "").lower() and
                search_str not in inc.get("description", "").lower()):
                continue
                
        sanitized.append({
            "id": inc_id,
            "reporter_id": inc.get("reporter_id"),
            "reporter_email": inc.get("reporter_email"),
            "reporter_name": inc.get("reporter_name"),
            "title": inc.get("title"),
            "incident_type": inc.get("incident_type"),
            "severity": inc.get("severity"),
            "ioc_type": inc.get("ioc_type"),
            "ioc_value": inc.get("ioc_value"),
            "description": inc.get("description"),
            "evidence": inc.get("evidence", []),
            "status": inc.get("status", "pending"),
            "admin_notes": inc.get("admin_notes", ""),
            "created_at": inc.get("created_at"),
            "updated_at": inc.get("updated_at")
        })
        
    # Sort by created_at descending by default
    try:
        sanitized.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    except Exception:
        pass
        
    return sanitized

@router.get("/incidents/{id}")
async def get_incident(id: str, current_user: dict = Depends(get_current_user)):
    inc_coll = get_collection("incidents")
    try:
        inc = await inc_coll.find_one({"_id": id})
        if not inc:
            inc = await inc_coll.find_one({"_id": ObjectId(id)})
    except Exception:
        inc = await inc_coll.find_one({"_id": id})
        
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    return {
        "id": str(inc["_id"]),
        "reporter_id": inc.get("reporter_id"),
        "reporter_email": inc.get("reporter_email"),
        "reporter_name": inc.get("reporter_name"),
        "title": inc.get("title"),
        "incident_type": inc.get("incident_type"),
        "severity": inc.get("severity"),
        "ioc_type": inc.get("ioc_type"),
        "ioc_value": inc.get("ioc_value"),
        "description": inc.get("description"),
        "evidence": inc.get("evidence", []),
        "status": inc.get("status", "pending"),
        "admin_notes": inc.get("admin_notes", ""),
        "created_at": inc.get("created_at"),
        "updated_at": inc.get("updated_at")
    }

@router.put("/incidents/{id}")
async def update_incident(id: str, req: IncidentUpdate, current_user: dict = Depends(get_current_user)):
    inc_coll = get_collection("incidents")
    try:
        inc = await inc_coll.find_one({"_id": id})
        if not inc:
            inc = await inc_coll.find_one({"_id": ObjectId(id)})
    except Exception:
        inc = await inc_coll.find_one({"_id": id})
        
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    # Security Rule: Only owner can modify, and only when status is pending
    if inc.get("reporter_id") != str(current_user["_id"]) and current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden: You are not eligible to modify this report.")
        
    if inc.get("status") != "pending" and current_user.get("role") != "admin":
        raise HTTPException(status_code=400, detail="Cannot edit incident once validated by administrative review.")
        
    update_fields = {}
    for k, v in req.dict(exclude_unset=True).items():
        if v is not None:
            update_fields[k] = v
            
    if not update_fields:
        raise HTTPException(status_code=400, detail="No updates requested")
        
    update_fields["updated_at"] = datetime.utcnow().isoformat()
    await inc_coll.update_one({"_id": inc["_id"]}, {"$set": update_fields})
    return {"message": "Incident updated successfully", "id": str(inc["_id"])}

@router.delete("/incidents/{id}")
async def delete_incident(id: str, current_user: dict = Depends(get_current_user)):
    inc_coll = get_collection("incidents")
    try:
        inc = await inc_coll.find_one({"_id": id})
        if not inc:
            inc = await inc_coll.find_one({"_id": ObjectId(id)})
    except Exception:
        inc = await inc_coll.find_one({"_id": id})
        
    if not inc:
        raise HTTPException(status_code=404, detail="Incident document not found")
        
    # Permission: Owner or admin can delete
    if inc.get("reporter_id") != str(current_user["_id"]) and current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden: Insufficient privileges to delete representation feed.")
        
    await inc_coll.delete_one({"_id": inc["_id"]})
    
    # Audit trace
    audit_coll = get_collection("audit_logs")
    await audit_coll.insert_one({
        "actor_id": str(current_user["_id"]),
        "action": "DELETE_INCIDENT",
        "target_id": str(inc["_id"]),
        "details": f"Deleted threat incident: {inc.get('title')}",
        "timestamp": datetime.utcnow().isoformat()
    })
    
    return {"message": "Incident deleted successfully"}

# --- Comments Endpoints ---

@router.post("/incidents/{id}/comments")
async def add_comment(id: str, req: CommentCreate, current_user: dict = Depends(get_current_user)):
    comments_coll = get_collection("comments")
    
    new_comment = {
        "incident_id": id,
        "user_id": str(current_user["_id"]),
        "display_name": current_user.get("display_name", "Anonymous User"),
        "email": current_user["email"],
        "content": req.content,
        "created_at": datetime.utcnow().isoformat()
    }
    await comments_coll.insert_one(new_comment)
    return {
        "id": str(new_comment.get("_id")),
        "display_name": new_comment["display_name"],
        "email": new_comment["email"],
        "content": new_comment["content"],
        "created_at": new_comment["created_at"]
    }

@router.get("/incidents/{id}/comments")
async def get_incident_comments(id: str, current_user: dict = Depends(get_current_user)):
    comments_coll = get_collection("comments")
    cursor = await comments_coll.find({"incident_id": id})
    comments = await cursor.to_array()
    
    sanitized = []
    for c in comments:
        sanitized.append({
            "id": str(c.get("_id")),
            "incident_id": c.get("incident_id"),
            "user_id": c.get("user_id"),
            "display_name": c.get("display_name"),
            "email": c.get("email"),
            "content": c.get("content"),
            "created_at": c.get("created_at")
        })
    try:
        sanitized.sort(key=lambda x: x.get("created_at", ""))
    except Exception:
        pass
    return sanitized

@router.delete("/comments/{comment_id}")
async def delete_comment(comment_id: str, current_user: dict = Depends(get_current_user)):
    comments_coll = get_collection("comments")
    try:
        c = await comments_coll.find_one({"_id": comment_id})
        if not c:
            c = await comments_coll.find_one({"_id": ObjectId(comment_id)})
    except Exception:
        c = await comments_coll.find_one({"_id": comment_id})
        
    if not c:
        raise HTTPException(status_code=404, detail="Comment not found")
        
    # Permission check: Owner or admin
    if c.get("user_id") != str(current_user["_id"]) and current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden: Insufficient privileges.")
        
    await comments_coll.delete_one({"_id": c["_id"]})
    return {"message": "Comment deleted successfully"}

# --- Threat Intelligence Lookups & Analytics ---

@router.get("/ioc/lookup")
async def ioc_lookup(q: str = Query(..., min_length=1), current_user: dict = Depends(get_current_user)):
    inc_coll = get_collection("incidents")
    
    # Lookup cases
    query = {"ioc_value": q.strip()}
    cursor = await inc_coll.find(query)
    results = await cursor.to_array()
    
    sanitized = []
    for inc in results:
        sanitized.append({
            "id": str(inc["_id"]),
            "title": inc.get("title"),
            "incident_type": inc.get("incident_type"),
            "severity": inc.get("severity"),
            "ioc_type": inc.get("ioc_type"),
            "ioc_value": inc.get("ioc_value"),
            "status": inc.get("status"),
            "created_at": inc.get("created_at")
        })
    return sanitized

@router.get("/stats/my")
async def get_my_stats(current_user: dict = Depends(get_current_user)):
    inc_coll = get_collection("incidents")
    comments_coll = get_collection("comments")
    
    user_id = str(current_user["_id"])
    submitted = await inc_coll.count_documents({"reporter_id": user_id})
    verified = await inc_coll.count_documents({"reporter_id": user_id, "status": "verified"})
    comments_count = await comments_coll.count_documents({"user_id": user_id})
    
    return {
        "submitted_reports": submitted,
        "verified_reports": verified,
        "comments_placed": comments_count,
        "trusted_score": (verified * 15) + (submitted * 5)
    }

@router.get("/incidents/{id}/related")
async def get_related_incidents(id: str, current_user: dict = Depends(get_current_user)):
    """Finds other incidents sharing the same IOC type or severity as the reference."""
    inc_coll = get_collection("incidents")
    try:
        ref = await inc_coll.find_one({"_id": id})
        if not ref:
            ref = await inc_coll.find_one({"_id": ObjectId(id)})
    except Exception:
        ref = await inc_coll.find_one({"_id": id})
        
    if not ref:
        raise HTTPException(status_code=404, detail="Reference incident not found")
        
    cursor = await inc_coll.find({
        "ioc_type": ref.get("ioc_type"),
        "_id": {"$ne": ref["_id"]}
    })
    related = await cursor.to_array()
    
    sanitized = []
    for inc in related:
        sanitized.append({
            "id": str(inc["_id"]),
            "title": inc.get("title"),
            "severity": inc.get("severity"),
            "ioc_value": inc.get("ioc_value"),
            "status": inc.get("status")
        })
    return sanitized[:5]
