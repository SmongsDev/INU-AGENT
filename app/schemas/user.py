from datetime import datetime
from typing import Optional
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

class LoginResponse(BaseModel):
    token: str
    user: SignUpResponse