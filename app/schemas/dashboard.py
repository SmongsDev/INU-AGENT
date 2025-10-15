from pydantic import BaseModel, Field
from datetime import datetime
from uuid import UUID


class DashboardCreate(BaseModel):
    dashboard: dict


class DashboardUpdate(BaseModel):
    dashboard: dict


class DashboardResponse(BaseModel):
    id: UUID
    dashboard: dict
    created_at: datetime

    class Config:
        from_attributes = True
