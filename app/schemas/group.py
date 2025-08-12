from pydantic import BaseModel
from typing import List, Optional
from app.schemas.user import UserResponse

class GroupBase(BaseModel):
    name: Optional[str] = None

class GroupCreate(GroupBase):
    pass

class GroupResponse(GroupBase):
    id: int
    users: List[UserResponse] = []

    class Config:
        from_attributes = True
