from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from datetime import datetime
from bson import ObjectId

from database import get_collection
from auth import hash_password, verify_password, create_access_token, get_current_user, require_admin
from models import RegisterRequest, LoginRequest, TokenResponse, UserUpdate, RoleChangeRequest

router = APIRouter(prefix="/api")

@router.post("/auth/register", response_model=dict)
async def register(req: RegisterRequest):
    users_coll = get_collection("users")
    existing_user = await users_coll.find_one({"email": req.email.lower()})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already registered"
        )
    
    new_user = {
        "email": req.email.lower(),
        "password_hash": hash_password(req.password),
        "display_name": req.display_name,
        "role": "user",
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }
    await users_coll.insert_one(new_user)
    
    # Audit log
    audit_coll = get_collection("audit_logs")
    await audit_coll.insert_one({
        "actor_id": "system",
        "action": "REGISTER_USER",
        "target_id": str(new_user.get("_id", "")),
        "details": f"User {req.email} registered on CyberTrace.",
        "timestamp": datetime.utcnow().isoformat()
    })
    
    return {"message": "Registration successful", "email": req.email}

@router.post("/auth/login", response_model=TokenResponse)
async def login(req: LoginRequest):
    users_coll = get_collection("users")
    user = await users_coll.find_one({"email": req.email.lower()})
    if not user or not verify_password(req.password, user.get("password_hash", "")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    # Check if we should elevate admin role flags or if they already have roles
    token_data = {
        "sub": user["email"],
        "role": user.get("role", "user"),
        "display_name": user.get("display_name", "User"),
        "id": str(user["_id"])
    }
    token = create_access_token(data=token_data)
    
    # Audit log
    audit_coll = get_collection("audit_logs")
    await audit_coll.insert_one({
        "actor_id": str(user["_id"]),
        "action": "LOGIN_USER",
        "target_id": str(user["_id"]),
        "details": f"User {user['email']} successfully logged in.",
        "timestamp": datetime.utcnow().isoformat()
    })
    
    user_data = {
        "id": str(user["_id"]),
        "email": user["email"],
        "display_name": user.get("display_name", "User"),
        "role": user.get("role", "user")
    }
    return {"access_token": token, "token_type": "bearer", "user": user_data}

@router.get("/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    # Sanitize user payload
    return {
        "id": str(current_user["_id"]),
        "email": current_user["email"],
        "display_name": current_user.get("display_name"),
        "role": current_user.get("role", "user"),
        "created_at": current_user.get("created_at"),
        "updated_at": current_user.get("updated_at")
    }

@router.put("/users/me")
async def update_me(req: UserUpdate, current_user: dict = Depends(get_current_user)):
    users_coll = get_collection("users")
    update_data = {}
    
    if req.display_name is not None:
        update_data["display_name"] = req.display_name
    if req.password is not None:
        update_data["password_hash"] = hash_password(req.password)
        
    if not update_data:
        raise HTTPException(status_code=400, detail="No valid update fields supplied")
        
    update_data["updated_at"] = datetime.utcnow().isoformat()
    await users_coll.update_one({"_id": current_user["_id"]}, {"$set": update_data})
    
    return {"message": "Profile updated successfully"}

@router.get("/users/{id}")
async def get_user_profile(id: str, current_user: dict = Depends(get_current_user)):
    users_coll = get_collection("users")
    try:
        # Match either ObjectId or string key
        user = await users_coll.find_one({"_id": id})
        if not user:
            user = await users_coll.find_one({"_id": ObjectId(id)})
    except Exception:
        user = await users_coll.find_one({"_id": id})
        
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    # Exclude password hashes from public profile lookups
    return {
        "id": str(user["_id"]),
        "display_name": user.get("display_name"),
        "role": user.get("role", "user"),
        "created_at": user.get("created_at")
    }

# --- Admin Restricted User Management Routes ---

@router.get("/users")
async def get_all_users(admin: dict = Depends(require_admin)):
    users_coll = get_collection("users")
    users_cursor = await users_coll.find()
    all_users = await users_cursor.to_array()
    
    sanitized_users = []
    for u in all_users:
        sanitized_users.append({
            "id": str(u["_id"]),
            "email": u["email"],
            "display_name": u.get("display_name"),
            "role": u.get("role", "user"),
            "created_at": u.get("created_at"),
            "updated_at": u.get("updated_at")
        })
    return sanitized_users

@router.put("/users/{id}/role")
async def change_user_role(id: str, req: RoleChangeRequest, admin: dict = Depends(require_admin)):
    if req.role not in ["user", "admin"]:
        raise HTTPException(status_code=400, detail="Invalid role type requested. Must be 'user' or 'admin'.")
        
    users_coll = get_collection("users")
    try:
        user = await users_coll.find_one({"_id": id})
        if not user:
            user = await users_coll.find_one({"_id": ObjectId(id)})
    except Exception:
        user = await users_coll.find_one({"_id": id})
        
    if not user:
        raise HTTPException(status_code=404, detail="User target not found.")
        
    await users_coll.update_one({"_id": user["_id"]}, {"$set": {
        "role": req.role,
        "updated_at": datetime.utcnow().isoformat()
    }})
    
    # Audit log
    audit_coll = get_collection("audit_logs")
    await audit_coll.insert_one({
        "actor_id": str(admin["_id"]),
        "action": "PROMOTE_USER_ROLE",
        "target_id": str(user["_id"]),
        "details": f"Admin updated role for {user['email']} to '{req.role}'.",
        "timestamp": datetime.utcnow().isoformat()
    })
    
    return {"message": "User role updated successfully", "id": str(user["_id"]), "role": req.role}

@router.delete("/users/{id}")
async def delete_user(id: str, admin: dict = Depends(require_admin)):
    users_coll = get_collection("users")
    try:
        user = await users_coll.find_one({"_id": id})
        if not user:
            user = await users_coll.find_one({"_id": ObjectId(id)})
    except Exception:
        user = await users_coll.find_one({"_id": id})
        
    if not user:
        raise HTTPException(status_code=404, detail="User target not found.")
        
    await users_coll.delete_one({"_id": user["_id"]})
    
    # Audit log
    audit_coll = get_collection("audit_logs")
    await audit_coll.insert_one({
        "actor_id": str(admin["_id"]),
        "action": "DELETE_USER",
        "target_id": str(user["_id"]),
        "details": f"Admin deleted user profile {user['email']}.",
        "timestamp": datetime.utcnow().isoformat()
    })
    
    return {"message": "User profile deleted successfully", "id": str(user["_id"])}
