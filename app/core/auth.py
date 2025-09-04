from fastapi import HTTPException
from sqlalchemy.orm import Session
from app.db.models import Session as SessionModel, User
from uuid import UUID


def get_group_id_from_token(token: str, db: Session) -> UUID:
    """
    Token을 통해 세션과 사용자를 검증하고 group_id를 반환합니다.
    
    Args:
        token: 세션 토큰
        db: 데이터베이스 세션
        
    Returns:
        UUID: 사용자의 group_id
        
    Raises:
        HTTPException: 세션 또는 사용자를 찾을 수 없는 경우
    """
    session = db.query(SessionModel).filter(SessionModel.token == str(token)).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    user = db.query(User).filter(User.id == session.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return user.group_id