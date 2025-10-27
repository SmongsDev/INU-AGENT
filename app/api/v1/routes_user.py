from fastapi import APIRouter, Depends, HTTPException, Response, Request
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
import uuid
from app.db.session import get_db
from app.db.models import User, Group, Session as UserSession
from app.schemas.user import (
    SignUpRequest, SignUpCreate, SignUpResponse,
    LoginRequest, SessionResponse,
    RefreshTokenResponse
)
from app.schemas.base import RoleType
from app.core.jwt_config import create_access_token, create_refresh_token, get_user_id_from_refresh_token

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
def login(
    request: Request,
    response: Response,
    login_data: LoginRequest,
    db: Session = Depends(get_db)
):
    # 사용자 검증
    user = db.query(User).filter(User.email == login_data.email).first()
    if not user or user.pw_hash != login_data.pw_hash:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # 기존 세션 만료 처리
    db.query(UserSession).filter(
        UserSession.user_id == user.id,
        UserSession.expired_at > datetime.now(timezone.utc)
    ).update({"expired_at": datetime.now(timezone.utc)})

    # 클라이언트 IP 자동 추출
    client_ip = request.client.host if request.client else "unknown"

    # JWT 토큰 생성
    token_data = {
        "user_id": str(user.id),
        "email": user.email,
        "group_id": str(user.group_id),
        "role": user.role.value
    }

    access_token = create_access_token(data=token_data)
    refresh_token = create_refresh_token(data={"user_id": str(user.id)})

    # Access Token 만료 시간 (1시간)
    access_expires = datetime.now(timezone.utc) + timedelta(hours=1)
    # Refresh Token 만료 시간 (7일)
    refresh_expires = datetime.now(timezone.utc) + timedelta(days=7)

    # 새 세션 생성 (JWT only)
    session = UserSession(
        user_id=user.id,
        refresh_token=refresh_token,  # JWT Refresh Token
        ip_addr=client_ip,  # 서버에서 자동 추출
        created_at=datetime.now(timezone.utc),
        expired_at=refresh_expires  # Refresh Token 만료 시간으로 설정
    )

    db.add(session)
    db.commit()

    # Refresh Token 쿠키 설정 (HttpOnly, Secure)
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        expires=refresh_expires.timestamp(),
        httponly=True,
        secure=True,
        samesite="lax"
    )

    return SessionResponse(
        access_token=access_token,  # JWT Access Token
        # refresh_token은 HttpOnly 쿠키로만 전달
        token_type="bearer",
        expires_at=access_expires,  # Access Token 만료 시간
        id=user.id,
        name=user.name,
        email=user.email,
        role=user.role
    )

@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    """
    로그아웃 - Refresh Token 쿠키 삭제 및 DB 세션 만료
    """
    # 쿠키에서 Refresh Token 읽기
    refresh_token = request.cookies.get('refresh_token')

    # Refresh Token이 있으면 DB에서 세션 만료 처리
    if refresh_token:
        db.query(UserSession).filter(
            UserSession.refresh_token == refresh_token
        ).update({"expired_at": datetime.now(timezone.utc)})
        db.commit()

    # Refresh Token 쿠키 삭제
    response.delete_cookie(
        key="refresh_token",
        httponly=True,
        secure=True,
        samesite="lax"
    )

    return {"message": "Successfully logged out"}

@router.post("/refresh", response_model=RefreshTokenResponse)
def refresh_access_token(
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Refresh Token을 사용하여 새로운 Access Token 발급
    HttpOnly 쿠키에서 자동으로 Refresh Token을 읽어옴
    """
    # 쿠키에서 Refresh Token 읽기
    refresh_token = request.cookies.get('refresh_token')

    if not refresh_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found. Please login again."
        )

    # Refresh Token 검증 및 user_id 추출
    try:
        user_id = get_user_id_from_refresh_token(refresh_token)
    except HTTPException:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # DB에서 Refresh Token 확인
    session = db.query(UserSession).filter(
        UserSession.refresh_token == refresh_token,
        UserSession.expired_at > datetime.now(timezone.utc)
    ).first()

    if not session:
        raise HTTPException(status_code=401, detail="Refresh token not found or expired")

    # 사용자 정보 조회
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # 새로운 Access Token 생성
    token_data = {
        "user_id": str(user.id),
        "email": user.email,
        "group_id": str(user.group_id),
        "role": user.role.value
    }

    access_token = create_access_token(data=token_data)
    access_expires = datetime.now(timezone.utc) + timedelta(hours=1)

    return RefreshTokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_at=access_expires
    )