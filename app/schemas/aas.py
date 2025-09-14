from uuid import UUID
from pydantic import BaseModel
from typing import Optional

class AASRequest(BaseModel):
    token: UUID
    flow_name: str
    flow_json: dict
    thumbnail_image: Optional[str] = None

class AASGetRequest(BaseModel):
    token: UUID

class AASDeleteRequest(BaseModel):
    token: UUID
    flow_name: str