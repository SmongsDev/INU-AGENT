from datetime import datetime
from typing import Optional, Dict, Any
from uuid import UUID
from pydantic import BaseModel, Field, IPvAnyAddress
from app.schemas.base import SourceProduct, TimestampedModel

class Event(TimestampedModel):
    id: UUID = Field(description="이벤트 고유 식별자")
    group_id: UUID = Field(description="그룹 ID")
    source_product: SourceProduct = Field(description="소스 제품")
    source_ip: Optional[IPvAnyAddress] = Field(None, description="소스 IP")
    user_agent: Optional[str] = Field(None, description="사용자 에이전트")
    created_at: datetime = Field(description="생성 시간")

class MLLog(BaseModel):
    id: UUID = Field(description="로그 ID")
    severity: Optional[int] = Field(None, description="심각도")
    confidence: Optional[float] = Field(None, description="신뢰도")

class FalsePositiveLog(BaseModel):
    id: UUID = Field(description="로그 ID")
    severity: Optional[int] = Field(None, description="심각도")
    confidence: Optional[float] = Field(None, description="신뢰도")
    reason: Optional[str] = Field(None, description="사유")
    result: Optional[Dict[str, Any]] = Field(None, description="분석 결과")

class FilterLog(BaseModel):
    id: UUID = Field(description="로그 ID")
    result: Dict[str, Any] = Field(description="필터링 결과")
    is_threat: bool = Field(default=False, description="위협 여부")

class Document(BaseModel):
    id: UUID = Field(description="문서 ID")
    content: str = Field(description="문서 내용")
    metadata: Optional[Dict[str, Any]] = Field(None, description="메타데이터")
    embedding: Optional[list[float]] = Field(None, description="임베딩 벡터")