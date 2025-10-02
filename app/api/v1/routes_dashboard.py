from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List
from app.db.session import get_db
from app.db.models import Group, Dashboard
from app.schemas.dashboard import DashboardCreate, DashboardResponse
from app.core.auth import get_group_id_from_token

router = APIRouter()

@router.get("/dashboard", response_model=List[DashboardResponse])
def get_dashboards(token: str = Query(...), db: Session = Depends(get_db)):
    # 토큰 검증 및 group_id 가져오기
    group_id = get_group_id_from_token(token, db)

    # group_id로 dashboard 조회
    dashboards = db.query(Dashboard).filter(Dashboard.group_id == group_id).all()
    return dashboards

@router.post("/dashboard", response_model=DashboardResponse)
def create_dashboard(dashboard_data: DashboardCreate, db: Session = Depends(get_db)):
    # 토큰 검증 및 group_id 가져오기
    group_id = get_group_id_from_token(dashboard_data.token, db)

    new_dashboard = Dashboard(
        group_id=group_id,
        dashboard=dashboard_data.dashboard
    )
    db.add(new_dashboard)
    db.commit()
    db.refresh(new_dashboard)
    return new_dashboard