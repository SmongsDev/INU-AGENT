from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import Meta_Data
from pydantic import BaseModel
from datetime import datetime
from app.core.auth import get_group_id_from_token

router = APIRouter()

class AgentFlowRequest(BaseModel):
    token: str
    agent_flow: dict

class AgentFlowGetRequest(BaseModel):
    token: str

@router.post("/agent_setup")
def save_agent_flow(request: AgentFlowRequest, db: Session = Depends(get_db)):
    group_id = get_group_id_from_token(request.token, db)
    
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
def get_agent_flow(request: AgentFlowGetRequest, db: Session = Depends(get_db)):
    group_id = get_group_id_from_token(request.token, db)
    
    meta_data = db.query(Meta_Data).filter(Meta_Data.group_id == group_id).first()
    if not meta_data:
        raise HTTPException(status_code=404, detail="Agent flow not found")
    
    return {
        "agent_flow": meta_data.agent_flow,
        "data_sync_time": meta_data.data_sync_time
    }