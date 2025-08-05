
from typing import Optional
from pydantic import BaseModel
from app.schemas.base import TimestampedModel
from app.schemas.cloudtrail import CloudTrailEvent

class Tier1(BaseModel):
    source_ip: str
    event_type: str
    error_code: Optional[str] = None

class Sample(TimestampedModel):
    tier1: Optional[Tier1] = None