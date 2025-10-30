from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from app.db.session import get_db
from app.db.models import Event, CloudTrail, AgentResult, AgentTotal
from app.core.auth import get_group_id_from_token
from app.schemas.automation import AutomationResponse, AutomationReasonResponse

router = APIRouter()


@router.get("/automation", response_model=List[AutomationResponse])
def get_automation_data(
    group_id: UUID = Depends(get_group_id_from_token),
    db: Session = Depends(get_db),
    severity: Optional[str] = Query(None, description="특정 심각도 필터 (HIGH, MEDIUM, LOW)"),
    start_time: Optional[datetime] = Query(None, description="시작 시간 필터"),
    end_time: Optional[datetime] = Query(None, description="종료 시간 필터"),
):
    """
    자동화를 위한 통합 위협 데이터 조회 API

    CloudTrail 정보와 Agent Results를 결합하여 반환합니다.

    Parameters:
    - **group_id**: 사용자의 그룹 ID (토큰에서 자동 추출)
    - **severity**: 심각도 필터 (HIGH, MEDIUM, LOW)
    - **start_time**: 시작 시간 필터
    - **end_time**: 종료 시간 필터

    Returns:
    - List[AutomationResponse]: 자동화 데이터 목록
        - name: 이벤트 이름 (CloudTrail)
        - source_ip: 소스 IP 주소 (CloudTrail)
        - event_time: 이벤트 발생 시간 (CloudTrail)
        - severity: 위협 심각도 (Agent Results)
        - mitre_mapping: MITRE ATT&CK 매핑 (Agent Results)
        - report: 분석 보고서 (Agent Results)

    Authorization: Bearer {access_token}
    """

    try:
        # 기본 쿼리: AgentResult를 메인으로 Event, CloudTrail, AgentTotal 조인
        query = db.query(
            AgentResult.id.label('event_id'),
            CloudTrail.event_name,
            CloudTrail.source_ip,
            CloudTrail.event_time,
            AgentResult.severity,
            AgentResult.mitre_mapping,
            AgentResult.report,
            AgentTotal.content,
        ).join(
            Event, AgentResult.id == Event.id
        ).join(
            CloudTrail, AgentResult.id == CloudTrail.id
        ).outerjoin(
            AgentTotal, AgentResult.id == AgentTotal.id
        ).filter(
            Event.group_id == group_id
        )

        # 심각도 필터 적용
        if severity:
            query = query.filter(AgentResult.severity == severity)

        # 시간 범위 필터 적용
        if start_time:
            query = query.filter(CloudTrail.event_time >= start_time)
        if end_time:
            query = query.filter(CloudTrail.event_time <= end_time)

        # 최신 순으로 정렬하고 limit 적용
        results = query.order_by(CloudTrail.event_time.desc()).all()

        # 응답 데이터 구성
        automation_data = []
        for result in results:
            automation_item = AutomationResponse(
                event_id=result.event_id,
                name=result.event_name or "Unknown Event",
                source_ip=str(result.source_ip) if result.source_ip else None,
                event_time=result.event_time,
                severity=result.severity.value if result.severity else None,
                mitre_mapping=result.mitre_mapping,
                report=result.report,
                detail=result.content,
            )
            automation_data.append(automation_item)

        return automation_data

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"자동화 데이터 조회 중 오류 발생: {str(e)}"
        )


@router.get("/automation/info", response_model=List[AutomationReasonResponse])
def get_automation_reason_response(
    group_id: UUID = Depends(get_group_id_from_token),
    db: Session = Depends(get_db),
    severity: Optional[str] = Query(None, description="특정 심각도 필터 (HIGH, MEDIUM, LOW)"),
    start_time: Optional[datetime] = Query(None, description="시작 시간 필터"),
    end_time: Optional[datetime] = Query(None, description="종료 시간 필터"),
):
    """
    자동화를 위한 Reason/Response 데이터 조회 API

    Agent Results의 reason과 response만 반환합니다.

    Parameters:
    - **group_id**: 사용자의 그룹 ID (토큰에서 자동 추출)
    - **severity**: 심각도 필터 (HIGH, MEDIUM, LOW)
    - **start_time**: 시작 시간 필터
    - **end_time**: 종료 시간 필터

    Returns:
    - List[AutomationReasonResponse]: Reason/Response 데이터 목록
        - reason: 위협 발생 이유
        - response: 대응 방안

    Authorization: Bearer {access_token}
    """

    try:
        # 기본 쿼리: AgentResult에서 reason, response와 CloudTrail의 event_id 조회
        query = db.query(
            CloudTrail.event_id,
            AgentResult.reason,
            AgentResult.response,
        ).join(
            Event, AgentResult.id == Event.id
        ).join(
            CloudTrail, AgentResult.id == CloudTrail.id
        ).filter(
            Event.group_id == group_id
        )

        # 심각도 필터 적용
        if severity:
            query = query.filter(AgentResult.severity == severity)

        # 시간 범위 필터 적용
        if start_time:
            query = query.filter(CloudTrail.event_time >= start_time)
        if end_time:
            query = query.filter(CloudTrail.event_time <= end_time)

        # 최신 순으로 정렬
        results = query.order_by(CloudTrail.event_time.desc()).all()

        # 응답 데이터 구성
        reason_response_data = []
        for result in results:
            item = AutomationReasonResponse(
                event_id=result.event_id,
                reason=result.reason,
                response=result.response,
            )
            reason_response_data.append(item)

        return reason_response_data

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Reason/Response 데이터 조회 중 오류 발생: {str(e)}"
        )
