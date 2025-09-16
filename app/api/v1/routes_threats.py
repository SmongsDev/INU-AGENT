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

def extract_role_name(user_identity: dict) -> str:
    """
    userIdentity에서 역할 이름을 추출

    Args:
        user_identity: CloudTrail의 userIdentity JSONB 데이터

    Returns:
        str: 역할 이름 또는 사용자 타입
    """
    if not user_identity:
        return "Unknown"

    try:
        user_type = user_identity.get('type', 'Unknown')

        # sessionName이 있는 경우 우선 확인 (AssumedRole, AwsApiCall 등에서 공통)
        session_name = user_identity.get('sessionName', '')
        if session_name:
            return session_name

        # AssumedRole의 경우 ARN에서 역할명 추출
        if user_type == 'AssumedRole':
            arn = user_identity.get('arn', '')
            if 'assumed-role/' in arn:
                # arn:aws:sts::123456789012:assumed-role/MyRole/session-name
                role_part = arn.split('assumed-role/')[1]
                role_name = role_part.split('/')[0]
                return role_name

        # AwsApiCall의 경우 추가 정보 확인
        elif user_type == 'AwsApiCall':
            # ARN이 있는 경우 역할명 추출 시도
            arn = user_identity.get('arn', '')
            if 'assumed-role/' in arn:
                role_part = arn.split('assumed-role/')[1]
                role_name = role_part.split('/')[0]
                return role_name
            elif arn:
                # 다른 형태의 ARN에서 마지막 부분 추출
                return arn.split('/')[-1] if '/' in arn else arn.split(':')[-1]

        # IAMUser의 경우
        elif user_type == 'IAMUser':
            user_name = user_identity.get('userName', '')
            return f"IAMUser:{user_name}" if user_name else "IAMUser"

        # Root 사용자의 경우
        elif user_type == 'Root':
            return "Root"

        # SAMLUser의 경우
        elif user_type == 'SAMLUser':
            saml_user = user_identity.get('userName', '')
            return f"SAML:{saml_user}" if saml_user else "SAMLUser"

        # WebIdentityUser의 경우
        elif user_type == 'WebIdentityUser':
            web_user = user_identity.get('userName', '')
            return f"WebIdentity:{web_user}" if web_user else "WebIdentityUser"

        # 기타 타입 - userName이나 principalId 확인
        else:
            user_name = user_identity.get('userName', '')
            if user_name:
                return f"{user_type}:{user_name}"

            principal_id = user_identity.get('principalId', '')
            if principal_id:
                return f"{user_type}:{principal_id}"

            return user_type

    except Exception:
        return "Unknown"

def format_predicted_threat(ml_prediction: dict, risk_level: str) -> str:
    """
    ML 예측 결과를 사용자 친화적 형태로 포맷

    Args:
        ml_prediction: ML 예측 데이터
        risk_level: 위험도 레벨

    Returns:
        str: 포맷된 위협 예측 문자열
    """
    if not ml_prediction:
        return "No Prediction"

    is_threat = ml_prediction.get('is_threat', False)
    confidence = ml_prediction.get('confidence', 0.0)
    confidence_pct = int(confidence * 100)

    if risk_level == "ml_detected":
        return f"ML Detected Threat ({confidence_pct}%)"
    elif is_threat:
        return f"High Threat ({confidence_pct}%)"
    elif risk_level == "high":
        return f"High Risk Pattern ({confidence_pct}%)"
    elif risk_level == "medium":
        return f"Medium Risk ({confidence_pct}%)"
    elif risk_level == "low":
        return f"Low Risk ({confidence_pct}%)"
    else:
        return f"Normal ({confidence_pct}%)"

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
            CloudTrail.source_ip.label('cloudtrail_source_ip'),
            CloudTrail.user_identity
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
        for filter_log, event_id, confidence, event_source_ip, created_at, event_name, event_time, cloudtrail_source_ip, user_identity in results:
            # filter_log.result에서 추가 정보 추출
            result_data = filter_log.result or {}
            ml_prediction = result_data.get('ml_prediction', {})
            risk_level = result_data.get('risk_level', 'unknown')

            # RoleName 추출
            role_name = extract_role_name(user_identity)

            # Predicted Threats 포맷
            predicted_threats = format_predicted_threat(ml_prediction, risk_level)

            threat_item = {
                "event_id": str(event_id),

                # CloudTrail 정보 (요청된 필드들)
                "event_name": event_name,
                "source_ip_address": str(cloudtrail_source_ip) if cloudtrail_source_ip else str(event_source_ip) if event_source_ip else None,
                "event_time": event_time.isoformat() if event_time else created_at.isoformat() if created_at else None,

                # 새로 추가된 필드들
                "role_name": role_name,
                "predicted_threats": predicted_threats,
                
                # 전체 result 데이터도 포함
                "filter_result": result_data,

                # 추가 메타 정보
                "created_at": created_at.isoformat() if created_at else None
            }

            threat_data.append(threat_item)

        return threat_data

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"위협 데이터 조회 중 오류 발생: {str(e)}")