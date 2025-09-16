from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from typing import List, Optional
from app.db.session import get_db
from app.db.models import FilterLog, MLLog, Event, CloudTrail, Session as SessionModel
from app.schemas.events import FilterLog as FilterLogSchema
from datetime import datetime

router = APIRouter()

def verify_token(token: str, db: Session) -> bool:
    session = db.query(SessionModel).filter(SessionModel.token == str(token)).first()
    return session is not None

@router.get("/threats", response_model=List[dict])
def get_threats(
    token: str = Query(..., description="인증 토큰"),
    db: Session = Depends(get_db),
    risk_level: Optional[str] = Query(None, description="필터링할 위험도 레벨 (high, medium, low, ml_detected, unknown)"),
    is_threat: Optional[bool] = Query(None, description="위협 여부로 필터링"),
    should_analyze: Optional[bool] = Query(None, description="분석 필요 여부로 필터링"),
    limit: Optional[int] = Query(None, description="반환할 최대 레코드 수")
):
    # 토큰 검증
    if not verify_token(token, db):
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    try:
        # 기본 쿼리: FilterLog와 관련 테이블들을 조인
        query = db.query(
            FilterLog,
            MLLog.event_id,
            MLLog.confidence,
            Event.source_ip,
            Event.created_at,
            CloudTrail.event_name,
            CloudTrail.event_time,
            CloudTrail.source_ip.label('cloudtrail_source_ip')
        ).join(
            MLLog, FilterLog.id == MLLog.id
        ).join(
            Event, MLLog.event_id == Event.id
        ).outerjoin(
            CloudTrail, Event.id == CloudTrail.id
        )

        # 필터링 조건 적용
        filters = []

        if is_threat is not None:
            filters.append(FilterLog.is_threat == is_threat)

        if should_analyze is not None:
            # JSONB 필드에서 should_analyze 값 확인
            filters.append(FilterLog.result['should_analyze'].astext.cast(db.Boolean) == should_analyze)

        if risk_level is not None:
            # JSONB 필드에서 risk_level 값 확인
            filters.append(FilterLog.result['risk_level'].astext == risk_level)

        if filters:
            query = query.filter(and_(*filters))

        # 최신 순으로 정렬하고 limit 적용
        results = query.order_by(Event.created_at.desc()).limit(limit).all()

        # 응답 데이터 구성
        threat_data = []
        for filter_log, event_id, confidence, event_source_ip, created_at, event_name, event_time, cloudtrail_source_ip in results:
            # filter_log.result에서 추가 정보 추출
            result_data = filter_log.result or {}

            threat_item = {
                "event_id": str(event_id),

                # CloudTrail 정보 (요청된 필드들)
                "event_name": event_name,
                "source_ip_address": str(cloudtrail_source_ip) if cloudtrail_source_ip else str(event_source_ip) if event_source_ip else None,
                "event_time": event_time.isoformat() if event_time else created_at.isoformat() if created_at else None,

                # ML 예측 정보
                "ml_prediction": result_data.get('ml_prediction', {}),

                # 전체 result 데이터도 포함
                "filter_result": result_data,

                # 추가 메타 정보
                "created_at": created_at.isoformat() if created_at else None
            }

            threat_data.append(threat_item)

        return threat_data

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"위협 데이터 조회 중 오류 발생: {str(e)}")