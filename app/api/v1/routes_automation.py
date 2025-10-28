from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from app.db.session import get_db
from app.db.models import Event, CloudTrail, AgentResult
from app.core.auth import get_group_id_from_token
from app.schemas.automation import AutomationResponse

router = APIRouter()


@router.get("/automation", response_model=List[AutomationResponse])
def get_automation_data(
    group_id: UUID = Depends(get_group_id_from_token),
    db: Session = Depends(get_db),
    limit: Optional[int] = Query(100, description="반환할 최대 레코드 수", le=1000),
    severity: Optional[str] = Query(None, description="특정 심각도 필터 (HIGH, MEDIUM, LOW)"),
    start_time: Optional[datetime] = Query(None, description="시작 시간 필터"),
    end_time: Optional[datetime] = Query(None, description="종료 시간 필터"),
):
    """
    자동화를 위한 통합 위협 데이터 조회 API

    CloudTrail 정보와 Agent Results를 결합하여 반환합니다.

    Parameters:
    - **group_id**: 사용자의 그룹 ID (토큰에서 자동 추출)
    - **limit**: 반환할 최대 레코드 수 (기본값: 100, 최대: 1000)
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
        # 기본 쿼리: AgentResult를 메인으로 Event, CloudTrail 조인
        query = db.query(
            AgentResult.id.label('event_id'),
            CloudTrail.event_name,
            CloudTrail.source_ip,
            CloudTrail.event_time,
            AgentResult.severity,
            AgentResult.mitre_mapping,
            AgentResult.report,
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

        # 최신 순으로 정렬하고 limit 적용
        results = query.order_by(CloudTrail.event_time.desc()).limit(limit).all()

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


@router.get("/automation/{event_id}", response_model=AutomationResponse)
def get_automation_data_by_id(
    event_id: UUID,
    group_id: UUID = Depends(get_group_id_from_token),
    db: Session = Depends(get_db),
):
    """
    특정 이벤트의 자동화 데이터 조회

    Parameters:
    - **event_id**: 조회할 이벤트 ID
    - **group_id**: 사용자의 그룹 ID (토큰에서 자동 추출)

    Returns:
    - AutomationResponse: 단일 자동화 데이터

    Authorization: Bearer {access_token}
    """

    try:
        # 특정 이벤트 조회
        result = db.query(
            AgentResult.id.label('event_id'),
            CloudTrail.event_name,
            CloudTrail.source_ip,
            CloudTrail.event_time,
            AgentResult.severity,
            AgentResult.mitre_mapping,
            AgentResult.report,
        ).join(
            Event, AgentResult.id == Event.id
        ).join(
            CloudTrail, AgentResult.id == CloudTrail.id
        ).filter(
            Event.group_id == group_id,
            AgentResult.id == event_id
        ).first()

        if not result:
            raise HTTPException(
                status_code=404,
                detail=f"Event not found: {event_id}"
            )

        # 응답 데이터 구성
        automation_item = AutomationResponse(
            event_id=result.event_id,
            name=result.event_name or "Unknown Event",
            source_ip=str(result.source_ip) if result.source_ip else None,
            event_time=result.event_time,
            severity=result.severity.value if result.severity else None,
            mitre_mapping=result.mitre_mapping,
            report=result.report,
        )

        return automation_item

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"자동화 데이터 조회 중 오류 발생: {str(e)}"
        )
