from pydantic import BaseModel
from typing import Optional

class UserBase(BaseModel):
    first_name: str
    last_name: str
    email: str
    role: str

class UserCreate(UserBase):
    group_id: int

class UserResponse(UserBase):
    id: int
    group_id: Optional[int] = None

    class Config:
        from_attributes = True
