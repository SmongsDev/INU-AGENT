from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, Field

class Metadata(BaseModel):
    group_id: UUID = Field(description="그룹 ID")
    data_sync_time: Optional[datetime] = Field(None, description="데이터 동기화 시간")

class MetadataUpdate(BaseModel):
    data_sync_time: datetime = Field(description="데이터 동기화 시간")