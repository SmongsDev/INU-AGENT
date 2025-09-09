from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import aas
from app.schemas.aas import AASRequest, AASGetRequest, AASDeleteRequest
from app.core.auth import get_group_id_from_token

router = APIRouter()

@router.post("/agent_draw")
def save_agent_draw(request: AASRequest, db: Session = Depends(get_db)):
    group_id = get_group_id_from_token(request.token, db)
    
    existing_aas = db.query(aas).filter(
        aas.group_id == group_id,
        aas.flow_name == request.flow_name
    ).first()
    
    if existing_aas:
        raise HTTPException(status_code=400, detail="Flow name already exists. Please use a different name.")
    
    new_aas = aas(
        group_id=group_id,
        flow_name=request.flow_name,
        flow_json=request.flow_json
    )
    db.add(new_aas)
    db.commit()
    
    return {"message": "Agent draw saved successfully"}

@router.get("/agent_draw")
def get_agent_draw(
    id: str = Query(...),
    token: str = Query(...),
    db: Session = Depends(get_db)
):
    group_id = get_group_id_from_token(token, db)
    
    aas_record = db.query(aas).filter(
        aas.flow_name == id,
        aas.group_id == group_id
    ).first()
    
    if not aas_record:
        raise HTTPException(status_code=404, detail="Agent draw not found")
    
    return {
        "id": aas_record.id,
        "flow_name": aas_record.flow_name,
        "flow_json": aas_record.flow_json
    }

@router.get("/agent_draws")
def get_all_agent_draws(token: str = Query(...), db: Session = Depends(get_db)):
    group_id = get_group_id_from_token(token, db)
    
    aas_records = db.query(aas).filter(aas.group_id == group_id).all()
    
    return {
        "agent_draws": [
            {
                "id": record.id,
                "flow_name": record.flow_name,
                "flow_json": record.flow_json
            }
            for record in aas_records
        ]
    }

@router.post("/agent_draw/delete")
def delete_agent_draw(request: AASDeleteRequest, db: Session = Depends(get_db)):
    group_id = get_group_id_from_token(request.token, db)
    
    aas_record = db.query(aas).filter(
        aas.flow_name == request.flow_name,
        aas.group_id == group_id
    ).first()
    
    if not aas_record:
        raise HTTPException(status_code=404, detail="Agent draw not found")
    
    db.delete(aas_record)
    db.commit()
    
    return {"message": "Agent draw deleted successfully"}