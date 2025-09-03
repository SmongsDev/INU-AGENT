from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import Session as SessionModel, User, aas
from app.schemas.aas import AASRequest

router = APIRouter()

@router.post("/agentdraw")
def save_agent_draw(request: AASRequest, db: Session = Depends(get_db)):
    session = db.query(SessionModel).filter(SessionModel.token == str(request.token)).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    user = db.query(User).filter(User.id == session.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    new_aas = aas(
        group_id=user.group_id,
        flow_name=request.flow_name,
        flow_json=request.flow_json
    )
    db.add(new_aas)
    db.commit()
    
    return {"message": "Agent draw saved successfully"}