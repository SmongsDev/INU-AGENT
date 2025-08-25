from decimal import Decimal
from typing import Any, Dict
from uuid import UUID
from pydantic import BaseModel, Field

class FalsePositiveLog(BaseModel):
    id: UUID = Field(description="거짓양성 로그 ID")
    severity: int = Field(description="심각도")
    confidence: Decimal = Field(description="신뢰도")
    reason: str = Field(description="거짓양성 이유")
    result: Dict[str, Any] = Field(description="결과 데이터")

class FalsePositiveLogCreate(BaseModel):
    severity: int = Field(description="심각도")
    confidence: Decimal = Field(description="신뢰도")
    reason: str = Field(description="거짓양성 이유")
    result: Dict[str, Any] = Field(description="결과 데이터")