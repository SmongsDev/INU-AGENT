from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, Field
from pydantic.networks import IPvAnyAddress
from app.schemas.base import TimestampedModel

class Session(TimestampedModel):
    id: UUID = Field(description="세션 ID")
    user_id: UUID = Field(description="사용자 ID")
    ip_addr: IPvAnyAddress = Field(description="IP 주소")
    token: str = Field(description="세션 토큰")
    created_at: datetime = Field(description="생성 시간")
    expired_at: Optional[datetime] = Field(None, description="만료 시간")

class SessionCreate(BaseModel):
    user_id: UUID = Field(description="사용자 ID")
    ip_addr: IPvAnyAddress = Field(description="IP 주소")
    token: str = Field(description="세션 토큰")
    expired_at: Optional[datetime] = Field(None, description="만료 시간")