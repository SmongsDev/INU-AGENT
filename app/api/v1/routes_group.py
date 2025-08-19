from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import Group
from app.schemas.group import GroupCreate

router = APIRouter()

@router.get("/groups")
def get_groups(db: Session = Depends(get_db)):
    groups = db.query(Group).all()
    return groups

@router.get("/groups/{group_id}")
def get_group(group_id: int, db: Session = Depends(get_db)):
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    return group

@router.post("/group")
def create_group(group: GroupCreate, db: Session = Depends(get_db)):
    new_group = Group(**group.model_dump())
    db.add(new_group)
    db.commit()
    db.refresh(new_group)
    return new_group