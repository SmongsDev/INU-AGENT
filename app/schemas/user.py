from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, Field, EmailStr
from app.schemas.base import RoleType, TimestampedModel

class SignUpRequest(BaseModel):
    name: str
    email: str
    pw_hash: str
    code: str

class SignUpCreate(BaseModel):
    name: str
    email: str
    pw_hash: str
    role: RoleType
    group_id: UUID

class SignUpResponse(BaseModel):
    id: UUID
    name: str
    email: str
    role: RoleType
    group_id: UUID
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class LoginRequest(BaseModel):
    email: str
    pw_hash: str
    # ip_addr는 서버에서 자동 추출

class SessionResponse(BaseModel):
    access_token: str  # JWT Access Token
    # refresh_token은 HttpOnly 쿠키로만 전달 (XSS 방어)
    token_type: str = "bearer"
    expires_at: datetime
    id: UUID
    name: str
    email: str
    role: RoleType

    class Config:
        from_attributes = True

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class RefreshTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime