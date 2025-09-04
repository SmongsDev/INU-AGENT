from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import Session as SessionModel, User, aas
from app.schemas.aas import AASRequest, AASGetRequest

router = APIRouter()

@router.post("/agent_draw")
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

@router.get("/agent_draw")
def get_agent_draw(
    id: str = Query(...),
    request: AASGetRequest = None,
    db: Session = Depends(get_db)
):
    if not request:
        raise HTTPException(status_code=400, detail="Token is required in request body")
        
    session = db.query(SessionModel).filter(SessionModel.token == str(request.token)).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    user = db.query(User).filter(User.id == session.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    aas_record = db.query(aas).filter(
        aas.flow_name == id,
        aas.group_id == user.group_id
    ).first()
    
    if not aas_record:
        raise HTTPException(status_code=404, detail="Agent draw not found")
    
    return {
        "id": aas_record.id,
        "group_id": str(aas_record.group_id),
        "flow_name": aas_record.flow_name,
        "flow_json": aas_record.flow_json
    }