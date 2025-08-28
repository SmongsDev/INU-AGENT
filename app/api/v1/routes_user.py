from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
import uuid
from app.db.session import get_db
from app.db.models import User, Group, Session as UserSession
from app.schemas.user import SignUpRequest, SignUpCreate, SignUpResponse, LoginRequest, SessionResponse
from app.schemas.base import RoleType

router = APIRouter()

@router.post("/signup", response_model=SignUpResponse)
def create_user(user: SignUpRequest, db: Session = Depends(get_db)):
    # 회사 코드로 그룹 검색
    group = db.query(Group).filter(Group.code == user.code).first()
    if not group:
        raise HTTPException(status_code=404, detail="Invalid company code")

    # 이메일 중복 체크
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # SignUpCreate 모델 생성
    user_create = SignUpCreate(
        name=user.name,
        email=user.email,
        pw_hash=user.pw_hash,
        role=RoleType.user,
        group_id=group.id
    )

    # 새 사용자 생성
    new_user = User(**user_create.model_dump())
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user

@router.post("/login", response_model=SessionResponse)
def login(response: Response, login_data: LoginRequest, db: Session = Depends(get_db)):
    # 사용자 검증
    user = db.query(User).filter(User.email == login_data.email).first()
    if not user or user.pw_hash != login_data.pw_hash:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # 기존 세션 만료 처리
    db.query(UserSession).filter(
        UserSession.user_id == user.id,
        UserSession.expired_at > datetime.now(timezone.utc)
    ).update({"expired_at": datetime.now(timezone.utc)})

    # 새 세션 생성
    token = str(uuid.uuid4())
    expires = datetime.now(timezone.utc) + timedelta(days=7)  # 7일 유효
    
    session = UserSession(
        user_id=user.id,
        token=token,
        ip_addr=login_data.ip_addr,
        created_at=datetime.now(timezone.utc),
        expired_at=expires
    )
    
    db.add(session)
    db.commit()

    # 쿠키 설정
    response.set_cookie(
        key="session_token",
        value=token,
        expires=expires.timestamp(),  # 만료 시간
        httponly=True,  # JavaScript에서 접근 불가
        secure=True,    # HTTPS에서만 전송
        samesite="lax"  # CSRF 보호
    )

    return SessionResponse(
        token=token,
        expires_at=expires,
        user=user
    )

@router.post("/logout")
def logout(response: Response, db: Session = Depends(get_db)):
    # 쿠키 삭제
    response.delete_cookie(
        key="session_token",
        httponly=True,
        secure=True,
        samesite="lax"
    )
    
    return {"message": "Successfully logged out"}