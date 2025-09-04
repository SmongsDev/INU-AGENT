from uuid import UUID
from pydantic import BaseModel

class AASRequest(BaseModel):
    token: UUID
    flow_name: str
    flow_json: dict

class AASGetRequest(BaseModel):
    token: UUID