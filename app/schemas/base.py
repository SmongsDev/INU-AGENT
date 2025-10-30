from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field
from enum import Enum

class RoleType(str, Enum):
    administrator = "administrator"
    security_officer = "security_officer"
    user = "user"

class NotifFreq(str, Enum):
    realtime = "realtime"
    hourly = "hourly"
    daily = "daily"

class NotifChannel(str, Enum):
    email = "email"
    push = "push"
    sms = "sms"
    discord = "discord"
    slack = "slack"

class SourceProduct(str, Enum):
    cloudtrail = "cloudtrail"
    cloudwatch = "cloudwatch"
    guardduty = "guardduty"

class SeverityLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"

class TimestampedModel(BaseModel):
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None