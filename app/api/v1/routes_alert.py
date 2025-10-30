from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from uuid import UUID
from datetime import date, timedelta
from app.db.session import get_db
from app.db.models import VwAlertsDailySummary, VwFalsePositiveTop
from app.core.auth import get_group_id_from_token

router = APIRouter()

@router.get("/alerts/summary")
def get_alerts_summary(
    group_id: UUID = Depends(get_group_id_from_token),
    db: Session = Depends(get_db)
):
    """
    Alert 요약 정보 조회 (최근 일주일 기준 severity별 카운트 및 전주 대비 증감)
    - Authorization: Bearer {access_token}

    Returns:
        {
            "high": 132,
            "high_change": 20,
            "high_change_rate": 17.86,
            "medium": 85,
            "medium_change": -10,
            "medium_change_rate": -10.53,
            "low": 27,
            "low_change": 5,
            "low_change_rate": 22.73
        }
    """

    try:
        # 날짜 범위 설정
        today = date.today()
        this_week_start = today - timedelta(days=6)  # 오늘 포함 7일
        last_week_start = today - timedelta(days=13)  # 저번주 시작
        last_week_end = today - timedelta(days=7)  # 저번주 끝

        # 이번주 데이터 조회 (오늘부터 6일 전까지)
        this_week_results = db.query(VwAlertsDailySummary).filter(
            VwAlertsDailySummary.group_id == group_id,
            VwAlertsDailySummary.day >= this_week_start,
            VwAlertsDailySummary.day <= today
        ).all()

        # 저번주 데이터 조회 (7일 전부터 13일 전까지)
        last_week_results = db.query(VwAlertsDailySummary).filter(
            VwAlertsDailySummary.group_id == group_id,
            VwAlertsDailySummary.day >= last_week_start,
            VwAlertsDailySummary.day <= last_week_end
        ).all()

        # 이번주 합계 계산
        this_week_high = sum(row.high for row in this_week_results)
        this_week_medium = sum(row.medium for row in this_week_results)
        this_week_low = sum(row.low for row in this_week_results)

        # 저번주 합계 계산
        last_week_high = sum(row.high for row in last_week_results)
        last_week_medium = sum(row.medium for row in last_week_results)
        last_week_low = sum(row.low for row in last_week_results)

        # 증가량 계산
        high_change = this_week_high - last_week_high
        medium_change = this_week_medium - last_week_medium
        low_change = this_week_low - last_week_low

        # 증가율 계산 (저번주가 0이면 0으로 처리)
        high_change_rate = (high_change / last_week_high * 100) if last_week_high > 0 else 0
        medium_change_rate = (medium_change / last_week_medium * 100) if last_week_medium > 0 else 0
        low_change_rate = (low_change / last_week_low * 100) if last_week_low > 0 else 0

        return {
            "high": this_week_high,
            "high_change": high_change,
            "high_change_rate": round(high_change_rate, 2),
            "medium": this_week_medium,
            "medium_change": medium_change,
            "medium_change_rate": round(medium_change_rate, 2),
            "low": this_week_low,
            "low_change": low_change,
            "low_change_rate": round(low_change_rate, 2)
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Alert 요약 조회 중 오류 발생: {str(e)}"
        )

@router.get("/alerts/top")
def get_alerts_top(
    db: Session = Depends(get_db)
):
    """
    False Positive TOP 10 Event Names 조회 (최근 24시간)
    - Authorization: Bearer {access_token}

    Returns:
        [
            {"event_name": "ConsoleLogin", "count": 1523},
            {"event_name": "AssumeRole", "count": 892},
            ...
        ]
    """

    try:
        # vw_false_positive_top View를 사용하여 TOP 10 event_name 조회
        results = db.query(VwFalsePositiveTop).all()

        return [
            {"event_name": row.event_name, "count": row.cnt}
            for row in results
        ]

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Alert TOP 10 조회 중 오류 발생: {str(e)}"
        )

@router.get("/alerts/timeseries")
def get_alerts_timeseries(
    group_id: UUID = Depends(get_group_id_from_token),
    db: Session = Depends(get_db)
):
    """
    Alert 주간 추이 조회 (오늘 기준 일주일치 일별 severity 카운트)
    - Authorization: Bearer {access_token}

    Returns:
        [
            {"day": "2025-10-23", "high": 10, "medium": 5, "low": 2},
            {"day": "2025-10-24", "high": 15, "medium": 8, "low": 3},
            ...
        ]
    """

    try:
        # 오늘 기준 7일 전부터 오늘까지
        today = date.today()
        start_day = today - timedelta(days=6)  # 오늘 포함 7일

        # VwAlertsDailySummary에서 일주일치 데이터 조회
        results = db.query(VwAlertsDailySummary).filter(
            VwAlertsDailySummary.group_id == group_id,
            VwAlertsDailySummary.day >= start_day,
            VwAlertsDailySummary.day <= today
        ).order_by(VwAlertsDailySummary.day).all()

        # 결과를 딕셔너리로 변환
        result_dict = {
            row.day: {"high": row.high, "medium": row.medium, "low": row.low}
            for row in results
        }

        # 7일간의 모든 날짜 생성 (데이터가 없는 날짜는 0으로)
        timeseries = []
        for i in range(7):
            day = start_day + timedelta(days=i)
            if day in result_dict:
                timeseries.append({
                    "day": day.isoformat(),
                    **result_dict[day]
                })
            else:
                timeseries.append({
                    "day": day.isoformat(),
                    "high": 0,
                    "medium": 0,
                    "low": 0
                })

        return timeseries

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Alert 주간 추이 조회 중 오류 발생: {str(e)}"
        )
