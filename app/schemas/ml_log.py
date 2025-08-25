from decimal import Decimal
from typing import Any, Dict, Optional
from uuid import UUID
from pydantic import BaseModel, Field

class MlLog(BaseModel):
    id: UUID = Field(description="ML 로그 ID")
    severity: int = Field(description="심각도")
    confidence: Decimal = Field(description="신뢰도")
    result: Dict[str, Any] = Field(description="결과 데이터")

class MlLogCreate(BaseModel):
    severity: int = Field(description="심각도")
    confidence: Decimal = Field(description="신뢰도")
    result: Dict[str, Any] = Field(description="결과 데이터")