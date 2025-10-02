from pydantic import BaseModel, Field
from datetime import datetime
from uuid import UUID


class DashboardCreate(BaseModel):
    token: str
    dashboard: dict


class DashboardResponse(BaseModel):
    id: int
    group_id: UUID
    dashboard: dict
    created_at: datetime

    class Config:
        from_attributes = True
