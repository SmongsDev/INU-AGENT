from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import Group

router = APIRouter()

@router.get("/dashboard")
def get_groups(db: Session = Depends(get_db)):
    groups = db.query(Group).all()
    return groups