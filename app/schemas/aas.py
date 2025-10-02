from uuid import UUID
from pydantic import BaseModel
from typing import Optional

class AASRequest(BaseModel):
    flow_name: str
    flow_json: dict
    thumbnail_image: Optional[str] = None

class AASDeleteRequest(BaseModel):
    flow_name: str