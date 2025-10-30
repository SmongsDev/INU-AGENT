from datetime import datetime
from typing import Optional, Dict, List
from pydantic import BaseModel, Field


class ChatSummaryRequest(BaseModel):
    """챗봇 요약 요청 스키마"""
    question: str = Field(..., description="사용자 질문 (날짜 정보 포함 가능)", max_length=500)


class CriticalThreat(BaseModel):
    """주요 고위험 위협 정보"""
    event_name: str = Field(..., description="이벤트 이름")
    event_time: str = Field(..., description="이벤트 발생 시간")
    confidence: float = Field(..., description="신뢰도 (0.0 ~ 1.0)")
    source_ip: Optional[str] = Field(None, description="소스 IP 주소")


class ThreatStats(BaseModel):
    """위협 통계 정보"""
    total_count: int = Field(..., description="전체 위협 건수")
    by_risk_level: Dict[str, int] = Field(..., description="위험도별 분포 (high/medium/low)")
    by_event_type: Dict[str, int] = Field(..., description="이벤트 타입별 건수")
    top_events: List[List] = Field(..., description="상위 5개 이벤트 [[이벤트명, 건수], ...]")
    critical_threats: List[CriticalThreat] = Field(..., description="주요 고위험 위협 (최대 10개)")


class ChatSummaryResponse(BaseModel):
    """챗봇 요약 응답 스키마"""
    summary: str = Field(..., description="AI가 생성한 요약문")
    stats: ThreatStats = Field(..., description="통계 데이터")
    period: Dict[str, str] = Field(..., description="조회 기간 {'start': 'YYYY-MM-DD', 'end': 'YYYY-MM-DD'}")
    extracted_from_question: bool = Field(
        default=True,
        description="날짜가 질문에서 추출되었는지 여부 (true: 질문에서 추출, false: 기본값 사용)"
    )
