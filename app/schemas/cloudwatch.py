from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import Field, IPvAnyAddress
from app.schemas.base import TimestampedModel

class CloudWatchEvent(TimestampedModel):
    id: UUID = Field(description="이벤트 고유 식별자")
    event_version: str = Field(description="이벤트 버전")
    event_time: datetime = Field(description="이벤트 발생 시간")
    event_source: str = Field(description="이벤트 소스")
    event_name: str = Field(description="이벤트 이름")
    aws_region: str = Field(description="AWS 리전")
    source_ip_address: Optional[IPvAnyAddress] = Field(None, description="소스 IP 주소")
    user_agent: Optional[str] = Field(None, description="사용자 에이전트")
    
    # JSON 필드
    userIdentity: Optional[dict] = Field(None, description="사용자 식별 정보")
    request_parameters: Optional[dict] = Field(None, description="요청 파라미터")
    response_elements: Optional[dict] = Field(None, description="응답 요소")
