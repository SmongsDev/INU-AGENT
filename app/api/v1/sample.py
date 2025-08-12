from fastapi import APIRouter, Depends, HTTPException
from app.schemas.sample import Tier1
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship, declarative_base, Session
import os
from app.db.session import get_db

import logging

Base = declarative_base()

router = APIRouter()

@router.post("/sample")
async def process_tier1_data(tier1_data: Tier1) -> str:
    return f"처리된 Data: IP {tier1_data.source_ip}에서 {tier1_data.event_type} 이벤트 발생, 에러 코드: {tier1_data.error_code or '없음'}"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True)

@router.get("/users/{user_id}")
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    logging.info(1)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user