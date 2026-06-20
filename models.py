from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Any
from datetime import datetime

# --- Pydantic Database Models ---

class UserSchema(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    email: EmailStr
    password_hash: str
    display_name: str
    role: str = "user" # user | admin
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True

class IncidentSchema(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    reporter_id: str
    reporter_email: str
    reporter_name: str
    title: str
    incident_type: str # phishing | malware | suspicious_ip | suspicious_url | other
    severity: str # Low | Medium | High | Critical
    ioc_type: str # ip | domain | url | file_hash
    ioc_value: str
    description: str
    evidence: List[str] = []
    status: str = "pending" # pending | verified | false_positive | under_review
    admin_notes: Optional[str] = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    verified_at: Optional[datetime] = None
    verified_by: Optional[str] = None

    class Config:
        populate_by_name = True

class CommentSchema(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    incident_id: str
    user_id: str
    display_name: str
    email: str
    content: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True

class AuditLogSchema(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    actor_id: str
    action: str
    target_id: str
    details: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True

class SessionSchema(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    user_id: str
    token_jti: str
    expires_at: datetime

    class Config:
        populate_by_name = True


# --- API Request / Response Schemas ---

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    display_name: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict

class UserUpdate(BaseModel):
    display_name: Optional[str] = None
    password: Optional[str] = None

class RoleChangeRequest(BaseModel):
    role: str

class IncidentCreate(BaseModel):
    title: str
    incident_type: str
    severity: str
    ioc_type: str
    ioc_value: str
    description: str
    evidence: Optional[List[str]] = []

class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    incident_type: Optional[str] = None
    severity: Optional[str] = None
    ioc_type: Optional[str] = None
    ioc_value: Optional[str] = None
    description: Optional[str] = None
    evidence: Optional[List[str]] = None

class AdminVerifyRequest(BaseModel):
    status: str
    admin_notes: Optional[str] = ""

class CommentCreate(BaseModel):
    content: str
