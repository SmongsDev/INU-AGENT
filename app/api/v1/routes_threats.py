from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from typing import List, Optional
from uuid import UUID
from app.db.session import get_db
from app.db.models import FalsePositiveLog, MLLog, Event, CloudTrail
from app.core.auth import get_group_id_from_token
from datetime import datetime

router = APIRouter()

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

@router.get("/threats", response_model=List[dict])
def get_threats(
    group_id: UUID = Depends(get_group_id_from_token),
    db: Session = Depends(get_db),
    limit: Optional[int] = Query(None, description="반환할 최대 레코드 수")
):
    """
    위협 데이터 조회
    - Authorization: Bearer {access_token}
    """

    try:
        # 기본 쿼리: FalsePositiveLog와 관련 테이블들을 조인
        query = db.query(
            FalsePositiveLog,
            MLLog.event_id,
            MLLog.confidence,
            Event.source_ip,
            Event.created_at,
            CloudTrail.event_name,
            CloudTrail.event_time,
            CloudTrail.source_ip.label('cloudtrail_source_ip'),
            CloudTrail.user_identity,
            CloudTrail.aws_region,
            CloudTrail.event_source,
            CloudTrail.user_agent,
            CloudTrail.request_parameters
        ).join(
            MLLog, FalsePositiveLog.id == MLLog.id
        ).join(
            Event, MLLog.event_id == Event.id
        ).outerjoin(
            CloudTrail, Event.id == CloudTrail.id
        ).filter(
            Event.group_id == group_id  # group_id 필터링 추가
        )

        # 최신 순으로 정렬하고 limit 적용
        results = query.order_by(Event.created_at.desc()).limit(limit).all()

        # 응답 데이터 구성
        threat_data = []
        for false_positive_log, event_id, confidence, event_source_ip, created_at, event_name, event_time, cloudtrail_source_ip, user_identity, aws_region, event_source, user_agent, request_parameters in results:
            # RoleName 추출
            role_name = extract_role_name(user_identity)

            # FalsePositiveLog 데이터 사용
            is_false_positive = false_positive_log.result if false_positive_log.result is not None else False
            fp_confidence = false_positive_log.confidence if false_positive_log.confidence is not None else 0.0
            fp_reason = false_positive_log.reason or "No reason provided"

            threat_item = {
                "event_id": str(event_id),

                # CloudTrail 정보 (기존 필드들)
                "event_name": event_name,
                "source_ip_address": str(cloudtrail_source_ip) if cloudtrail_source_ip else str(event_source_ip) if event_source_ip else None,
                "event_time": event_time.isoformat() if event_time else created_at.isoformat() if created_at else None,

                # 새로 추가된 CloudTrail 필드들
                "aws_region": aws_region,
                "event_source": event_source,
                "user_agent": user_agent,
                "request_parameters": request_parameters,

                # 기존 필드들
                "role_name": role_name,
                "confidence": confidence,

                # FalsePositiveLog 정보
                "is_false_positive": is_false_positive,
                "false_positive_confidence": fp_confidence,
                "false_positive_reason": fp_reason,

                # 추가 메타 정보
                "created_at": created_at.isoformat() if created_at else None
            }

            threat_data.append(threat_item)

        return threat_data

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"위협 데이터 조회 중 오류 발생: {str(e)}")