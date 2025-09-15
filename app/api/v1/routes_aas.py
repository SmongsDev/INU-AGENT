from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import aas
from app.schemas.aas import AASRequest, AASGetRequest, AASDeleteRequest
from app.core.auth import get_group_id_from_token
from app.services.s3_service import S3Service

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

    thumbnail_s3_key = None
    if request.thumbnail_image:
        s3_service = S3Service()
        thumbnail_s3_key = s3_service.upload_base64_image(request.thumbnail_image)
        if not thumbnail_s3_key:
            raise HTTPException(status_code=500, detail="Failed to upload thumbnail image to S3")

    new_aas = aas(
        group_id=group_id,
        flow_name=request.flow_name,
        flow_json=request.flow_json,
        thumbnail_s3_key=thumbnail_s3_key
    )
    db.add(new_aas)
    db.commit()

    return {
        "message": "Agent draw saved successfully"
    }

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

    s3_service = S3Service()
    thumbnail_url = None
    if aas_record.thumbnail_s3_key:
        thumbnail_url = s3_service.get_file_url(aas_record.thumbnail_s3_key)

    return {
        "id": aas_record.id,
        "flow_name": aas_record.flow_name,
        "flow_json": aas_record.flow_json,
        "thumbnail_url": thumbnail_url
    }

@router.get("/agent_draws")
def get_all_agent_draws(token: str = Query(...), db: Session = Depends(get_db)):
    group_id = get_group_id_from_token(token, db)

    aas_records = db.query(aas).filter(aas.group_id == group_id).all()

    s3_service = S3Service()
    agent_draws = []

    for record in aas_records:
        thumbnail_url = None
        if record.thumbnail_s3_key:
            thumbnail_url = s3_service.get_file_url(record.thumbnail_s3_key)

        agent_draws.append({
            "id": record.id,
            "flow_name": record.flow_name,
            "flow_json": record.flow_json,
            "thumbnail_url": thumbnail_url
        })

    return {"agent_draws": agent_draws}

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