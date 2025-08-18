from datetime import datetime
from typing import Optional, UUID
from pydantic import BaseModel, Field
from app.schemas.base import TimestampedModel

class Group(TimestampedModel):
    id: UUID = Field(description="그룹 ID")
    name: str = Field(description="회사 이름")
    created_at: datetime = Field(description="생성 시간")