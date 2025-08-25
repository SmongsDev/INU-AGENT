from typing import Any, Dict
from uuid import UUID
from pydantic import BaseModel, Field

class FilterLog(BaseModel):
    id: UUID = Field(description="필터 로그 ID")
    result: Dict[str, Any] = Field(description="결과 데이터")

class FilterLogCreate(BaseModel):
    result: Dict[str, Any] = Field(description="결과 데이터")