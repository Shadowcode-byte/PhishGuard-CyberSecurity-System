from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional, List
from datetime import datetime
from uuid import UUID
from enum import Enum


# ── Auth Schemas ──────────────────────────────────────────────────────────────

class UserRegister(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=100)
    # FIX: Added terms_accepted field — backend auth.py requires it but it was
    # missing from the schema, so all registration attempts returned 422
    # "Validation error" and the frontend showed no error (just reset).
    terms_accepted: bool 

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


# ── User Schemas ──────────────────────────────────────────────────────────────

class UserOut(BaseModel):
    id: UUID
    email: str
    username: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None


# ── Scan Schemas ──────────────────────────────────────────────────────────────

class URLScanRequest(BaseModel):
    url: str = Field(..., min_length=5, max_length=2048)


class MessageScanRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=5000)
    sender: Optional[str] = None


class URLScanResponse(BaseModel):
    scan_id: UUID
    label: str
    confidence: float
    risk_score: int = 0
    reasons: List[str]
    detection_mode: str
    ai_analysis: Optional[dict] = None
    threat_explanation: Optional[dict] = None
    vt_result: Optional[dict] = None
    created_at: datetime


class MessageScanResponse(BaseModel):
    scan_id: UUID
    label: str
    final_score: float
    rule_score: float
    confidence_level: str
    risk_score: int = 0
    reasons: List[str]
    language: str
    api_used: bool
    ai_analysis: Optional[dict] = None
    created_at: datetime


class FileScanResponse(BaseModel):
    file_id: UUID
    filename: str
    status: str
    message: str


# ── History Schemas ───────────────────────────────────────────────────────────

class ScanHistoryItem(BaseModel):
    id: UUID
    scan_type: str
    input_data: str
    label: str
    confidence: float
    created_at: datetime

    class Config:
        from_attributes = True


class ScanHistoryResponse(BaseModel):
    items: List[ScanHistoryItem]
    total: int
    page: int
    per_page: int


# ── Admin Schemas ─────────────────────────────────────────────────────────────

class AdminStats(BaseModel):
    total_users: int
    total_scans: int
    scans_today: int
    phishing_detected: int
    fraud_detected: int
    safe_scans: int
    url_scans: int
    message_scans: int
    file_scans: int


class AdminUserList(BaseModel):
    items: List[UserOut]
    total: int


class RoleUpdate(BaseModel):
    role: str = Field(..., pattern="^(user|analyst|admin)$")


# ── API Key Schemas ───────────────────────────────────────────────────────────

class APIKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    expires_days: Optional[int] = Field(None, ge=1, le=365)


class APIKeyResponse(BaseModel):
    id: UUID
    name: str
    key: Optional[str] = None  # Only returned on creation
    is_active: bool
    scans_used: int
    created_at: datetime
    expires_at: Optional[datetime]

    class Config:
        from_attributes = True


# ── Admin Extended Schemas ────────────────────────────────────────────────────

class AdminCreateUser(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=100)
    role: str = Field(default="user", pattern="^(user|analyst|admin)$")


class AdminResetPassword(BaseModel):
    new_password: str = Field(..., min_length=8, max_length=100)


class AuditLogOut(BaseModel):
    id: str
    user_id: Optional[str]
    username: str
    action: str
    resource: Optional[str]
    resource_id: Optional[str]
    ip_address: Optional[str]
    details: Optional[dict]
    created_at: str
