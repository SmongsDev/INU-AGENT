from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import  Field, IPvAnyAddress
from app.schemas.base import TimestampedModel

class CloudTrailEvent(TimestampedModel):
    id: UUID = Field(description="이벤트 고유 식별자 (UUID)")
    event_id: str = Field(description="AWS CloudTrail 이벤트 ID")
    
    # 이벤트 기본 정보
    event_version: Optional[str] = Field(None, description="이벤트 버전")
    event_time: datetime = Field(description="이벤트 발생 시간")
    event_source: str = Field(description="이벤트 소스 (AWS 서비스)")
    event_name: str = Field(description="이벤트 작업 이름")
    event_category: Optional[str] = Field(None, description="이벤트 카테고리")
    event_type: Optional[str] = Field(None, description="이벤트 타입")
    aws_region: Optional[str] = Field(None, description="AWS 리전")
    read_only: Optional[bool] = Field(None, description="읽기 전용 작업 여부")
    
    # 요청/응답 식별자
    request_id: Optional[str] = Field(None, description="요청 ID")
    
    # 네트워크 정보
    source_ip: Optional[IPvAnyAddress] = Field(None, description="소스 IP 주소")
    user_agent: Optional[str] = Field(None, description="사용자 에이전트")
    
    # 관리 및 계정 정보
    management_event: Optional[bool] = Field(None, description="관리 이벤트 여부")
    recipient_account_id: Optional[str] = Field(None, description="수신자 계정 ID")
    session_credential_from_console: Optional[str] = Field(None, description="콘솔 세션 자격 증명")
    shared_event_id: Optional[str] = Field(None, description="공유 이벤트 ID")
    
    # 에러 정보
    error_code: Optional[str] = Field(None, description="에러 코드")
    error_message: Optional[str] = Field(None, description="에러 메시지")
    
    # ML 분석 결과
    is_false_positive: Optional[bool] = Field(None, description="ML 기반 오탐 여부 판정")
    
    # JSON 필드들
    user_identity: Optional[dict] = Field(None, description="사용자 식별 정보")
    tls_details: Optional[dict] = Field(None, description="TLS 상세 정보")
    request_parameters: Optional[dict] = Field(None, description="요청 파라미터")
    response_elements: Optional[dict] = Field(None, description="응답 요소")
    insight_details: Optional[dict] = Field(None, description="인사이트 상세 정보")
    resources: Optional[dict] = Field(None, description="리소스 정보")

    # 타임스탬프
    created_at: datetime = Field(description="이벤트 생성 시간")