from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from uuid import UUID
from app.db.session import get_db
from app.db.models import Group, Dashboard
from app.schemas.dashboard import DashboardCreate, DashboardResponse
from app.core.auth import get_group_id_from_token

router = APIRouter()

@router.get("/dashboard", response_model=List[DashboardResponse])
def get_dashboards(
    group_id: UUID = Depends(get_group_id_from_token),
    db: Session = Depends(get_db)
):
    """
    Dashboard 목록 조회
    - JWT: Authorization: Bearer {access_token}
    """
    # group_id로 dashboard 조회
    dashboards = db.query(Dashboard).filter(Dashboard.group_id == group_id).all()
    return dashboards

@router.post("/dashboard", response_model=DashboardResponse)
def create_dashboard(
    dashboard_data: DashboardCreate,
    group_id: UUID = Depends(get_group_id_from_token),
    db: Session = Depends(get_db)
):
    """
    Dashboard 생성
    - JWT: Authorization: Bearer {access_token}
    """
    new_dashboard = Dashboard(
        group_id=group_id,
        dashboard=dashboard_data.dashboard
    )
    db.add(new_dashboard)
    db.commit()
    db.refresh(new_dashboard)
    return new_dashboard

@router.post("/dashboard/{dashboard_id}")
def delete_dashboard(
    dashboard_id: UUID,
    group_id: UUID = Depends(get_group_id_from_token),
    db: Session = Depends(get_db)
):
    """
    Dashboard 삭제
    - JWT: Authorization: Bearer {access_token}
    - dashboard_id: 삭제할 Dashboard의 UUID
    """
    # group_id 검증과 함께 dashboard 조회
    dashboard = db.query(Dashboard).filter(
        Dashboard.id == dashboard_id,
        Dashboard.group_id == group_id
    ).first()

    if not dashboard:
        raise HTTPException(status_code=404, detail="Dashboard not found")

    db.delete(dashboard)
    db.commit()

    return {"message": "Dashboard deleted successfully"}