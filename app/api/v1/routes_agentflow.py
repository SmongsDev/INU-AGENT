from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import Session as SessionModel, User, Meta_Data
from pydantic import BaseModel
from datetime import datetime

router = APIRouter()

class AgentFlowRequest(BaseModel):
    token: str
    agent_flow: dict

@router.post("/agentflow")
def save_agent_flow(request: AgentFlowRequest, db: Session = Depends(get_db)):
    session = db.query(SessionModel).filter(SessionModel.token == request.token).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    user = db.query(User).filter(User.id == session.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    meta_data = db.query(Meta_Data).filter(Meta_Data.group_id == user.group_id).first()
    if meta_data:
        meta_data.agent_flow = request.agent_flow
        meta_data.data_sync_time = datetime.now()
    else:
        meta_data = Meta_Data(
            group_id=user.group_id,
            agent_flow=request.agent_flow,
            data_sync_time=datetime.now()
        )
        db.add(meta_data)
    
    db.commit()
    return {"message": "Agent flow saved successfully"}