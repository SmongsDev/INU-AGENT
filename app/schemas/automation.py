from datetime import datetime
from typing import Optional, Dict, Any
from uuid import UUID
from pydantic import BaseModel, Field, IPvAnyAddress
from app.schemas.base import SeverityLevel


class AutomationResponse(BaseModel):
    """
    자동화 API 응답 모델
    CloudTrail과 Agent Results를 결합한 데이터
    """
    # Event 정보
    event_id: UUID = Field(description="이벤트 ID")

    # CloudTrail 정보
    name: str = Field(description="이벤트 이름 (CloudTrail event_name)")
    source_ip: Optional[str] = Field(None, description="소스 IP 주소 (CloudTrail source_ip)")
    event_time: datetime = Field(description="이벤트 발생 시간 (CloudTrail event_time)")

    # Agent Results 정보
    severity: Optional[str] = Field(None, description="위협 심각도 (agent_results severity)")
    mitre_mapping: Optional[str] = Field(None, description="MITRE ATT&CK 매핑 (agent_results mitre_mapping)")
    report: Optional[str] = Field(None, description="분석 보고서 (agent_results report)")

    # Agent Total 정보
    detail: Optional[Dict[str, Any]] = Field(None, description="에이전트 상세 정보 (agent_total content)")

    class Config:
        from_attributes = True


class AutomationReasonResponse(BaseModel):
    """
    자동화 Reason/Response API 응답 모델
    Agent Results의 id, reason, response 반환
    """
    id: UUID = Field(description="이벤트 ID")
    reason: Optional[str] = Field(None, description="위협 발생 이유 (agent_results reason)")
    response: Optional[str] = Field(None, description="대응 방안 (agent_results response)")

    class Config:
        from_attributes = True
