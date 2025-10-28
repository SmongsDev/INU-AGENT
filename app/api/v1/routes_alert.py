from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from uuid import UUID
from app.db.session import get_db
from app.db.models import VwAlertsSummary, VwAlertsTop
from app.core.auth import get_group_id_from_token

router = APIRouter()

@router.get("/alerts/summary")
def get_alerts_summary(
    group_id: UUID = Depends(get_group_id_from_token),
    db: Session = Depends(get_db)
):
    """
    Alert 요약 정보 조회 (severity별 카운트)
    - Authorization: Bearer {access_token}

    Returns:
        {
            "high": 132,
            "medium": 85,
            "low": 27
        }
    """

    try:
        # vw_alerts_summary View를 사용하여 group_id별 집계 데이터 조회
        result = db.query(VwAlertsSummary).filter(
            VwAlertsSummary.group_id == group_id
        ).first()

        return {
            "high": result.high if result else 0,
            "medium": result.medium if result else 0,
            "low": result.low if result else 0
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Alert 요약 조회 중 오류 발생: {str(e)}"
        )

@router.get("/alerts/top")
def get_alerts_top(
    group_id: UUID = Depends(get_group_id_from_token),
    db: Session = Depends(get_db)
):
    """
    Alert TOP 10 Event Names 조회
    - Authorization: Bearer {access_token}

    Returns:
        [
            {"event_name": "ConsoleLogin", "count": 1523},
            {"event_name": "AssumeRole", "count": 892},
            ...
        ]
    """

    try:
        # vw_alerts_top View를 사용하여 group_id별 TOP 10 event_name 조회
        results = db.query(VwAlertsTop).filter(
            VwAlertsTop.group_id == group_id
        ).order_by(
            VwAlertsTop.count.desc()
        ).limit(10).all()

        return [
            {"event_name": row.event_name, "count": row.count}
            for row in results
        ]

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Alert TOP 10 조회 중 오류 발생: {str(e)}"
        )
