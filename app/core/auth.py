from fastapi import HTTPException, Header, Query, Depends
from sqlalchemy.orm import Session
from app.db.models import Session as SessionModel, User
from app.db.session import get_db
from app.core.jwt_config import get_current_user_from_token
from uuid import UUID
from typing import Optional
from datetime import datetime, timezone


def get_group_id_from_token(
    authorization: str = Header(..., alias="Authorization"),
    db: Session = Depends(get_db)
) -> UUID:
    """
    JWT Access Token을 검증하고 group_id를 반환합니다.

    Args:
        authorization: Authorization 헤더 (Bearer {JWT Access Token})
        db: 데이터베이스 세션

    Returns:
        UUID: 사용자의 group_id

    Raises:
        HTTPException: 토큰이 유효하지 않은 경우
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization header format. Use 'Bearer {token}'"
        )

    user_info = get_current_user_from_token(authorization)
    return user_info["group_id"]


def get_user_from_token(
    authorization: str = Header(..., alias="Authorization"),
    db: Session = Depends(get_db)
) -> User:
    """
    JWT Access Token을 검증하고 사용자 정보를 반환합니다.

    Args:
        authorization: Authorization 헤더 (Bearer {JWT Access Token})
        db: 데이터베이스 세션

    Returns:
        User: 사용자 객체

    Raises:
        HTTPException: 토큰이 유효하지 않거나 사용자를 찾을 수 없는 경우
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization header format. Use 'Bearer {token}'"
        )

    user_info = get_current_user_from_token(authorization)
    user = db.query(User).filter(User.id == user_info["user_id"]).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user