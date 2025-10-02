from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from uuid import UUID
from app.db.session import get_db
from app.db.models import Meta_Data
from pydantic import BaseModel
from datetime import datetime
from app.core.auth import get_group_id_from_token

router = APIRouter()

class AgentFlowRequest(BaseModel):
    agent_flow: dict
    
@router.post("/agent_setup")
def save_agent_flow(
    request: AgentFlowRequest,
    group_id: UUID = Depends(get_group_id_from_token),
    db: Session = Depends(get_db)
):
    """
    Agent Flow 저장
    - Authorization: Bearer {access_token}
    """
    
    meta_data = db.query(Meta_Data).filter(Meta_Data.group_id == group_id).first()
    if meta_data:
        meta_data.agent_flow = request.agent_flow
        meta_data.data_sync_time = datetime.now()
    else:
        meta_data = Meta_Data(
            group_id=group_id,
            agent_flow=request.agent_flow,
            data_sync_time=datetime.now()
        )
        db.add(meta_data)
    
    db.commit()
    return {"message": "Agent flow saved successfully"}

@router.get("/agent_setup")
def get_agent_flow(
    group_id: UUID = Depends(get_group_id_from_token),
    db: Session = Depends(get_db)
):
    """
    Agent Flow 조회
    - Authorization: Bearer {access_token}
    """
    
    meta_data = db.query(Meta_Data).filter(Meta_Data.group_id == group_id).first()
    if not meta_data:
        raise HTTPException(status_code=404, detail="Agent flow not found")
    
    return {
        "agent_flow": meta_data.agent_flow,
        "data_sync_time": meta_data.data_sync_time
    }

@router.post("/agent_setup/delete")
def delete_agent_flow(
    group_id: UUID = Depends(get_group_id_from_token),
    db: Session = Depends(get_db)
):
    """
    Agent Flow 삭제
    - Authorization: Bearer {access_token}
    """
    
    meta_data = db.query(Meta_Data).filter(Meta_Data.group_id == group_id).first()
    if not meta_data:
        raise HTTPException(status_code=404, detail="Agent flow not found")
    
    db.delete(meta_data)
    db.commit()
    
    return {"message": "Agent flow deleted successfully"}