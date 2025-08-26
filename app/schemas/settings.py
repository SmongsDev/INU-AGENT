from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, Field, EmailStr
from app.schemas.base import NotifChannel, NotifFreq

class Settings(BaseModel):
    group_id: UUID = Field(description="그룹 ID")
    notif_email: Optional[str] = Field(None, description="알림 이메일")
    notif_enabled: bool = Field(default=False, description="알림 활성화 여부")
    notif_channel: Optional[NotifChannel] = Field(None, description="알림 채널")
    notif_freq: NotifFreq = Field(default=NotifFreq.realtime, description="알림 빈도")

class Meta_Data(BaseModel):
    group_id: UUID = Field(description="그룹 ID")
    data_sync_time: datetime = Field(None, description="데이터 동기화 시간")