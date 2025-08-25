from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, Field, EmailStr
from app.schemas.base import RoleType, TimestampedModel

class User(TimestampedModel):
    id: UUID = Field(description="사용자 ID")
    group_id: UUID = Field(description="그룹 ID")
    name: str = Field(description="사용자 이름")
    email: EmailStr = Field(description="이메일")
    pw_hash: str = Field(description="비밀번호 해시")
    role: RoleType = Field(description="사용자 역할")
    created_at: datetime = Field(description="생성 시간")
    updated_at: datetime = Field(description="수정 시간")

class UserCreate(TimestampedModel):
    id: UUID = Field(description="사용자 ID")
    group_id: UUID = Field(description="그룹 ID")
    name: str = Field(description="사용자 이름")
    email: EmailStr = Field(description="이메일")
    pw_hash: str = Field(description="비밀번호 해시")
    role: RoleType = Field(description="사용자 역할")

