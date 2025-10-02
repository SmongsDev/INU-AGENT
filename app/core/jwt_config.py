from datetime import datetime, timedelta, timezone
from typing import Optional, Dict
from jose import JWTError, jwt
from fastapi import HTTPException, Depends, Header
from sqlalchemy.orm import Session
from uuid import UUID
import os
import sys

# JWT 설정 (환경 변수에서 로드)
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = os.getenv("JWT_ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1시간
REFRESH_TOKEN_EXPIRE_DAYS = 7  # 7일

# SECRET_KEY 검증 (필수)
if not SECRET_KEY:
    print("ERROR: JWT_SECRET_KEY environment variable is not set")
    sys.exit(1)

if not ALGORITHM:
    print("ERROR: JWT_ALGORITHM environment variable is not set")
    sys.exit(1)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Access Token 생성

    Args:
        data: JWT payload에 포함할 데이터
        expires_delta: 토큰 만료 시간 (기본값: 1시간)

    Returns:
        str: 생성된 JWT 토큰
    """
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access"
    })

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Refresh Token 생성

    Args:
        data: JWT payload에 포함할 데이터
        expires_delta: 토큰 만료 시간 (기본값: 7일)

    Returns:
        str: 생성된 JWT Refresh 토큰
    """
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "refresh"
    })

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str, token_type: str = "access") -> Dict:
    """
    JWT 토큰 검증

    Args:
        token: 검증할 JWT 토큰
        token_type: 토큰 타입 ("access" 또는 "refresh")

    Returns:
        Dict: 디코딩된 payload

    Raises:
        HTTPException: 토큰이 유효하지 않은 경우
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # 토큰 타입 확인
        if payload.get("type") != token_type:
            raise HTTPException(
                status_code=401,
                detail=f"Invalid token type. Expected {token_type}"
            )

        # 만료 시간(exp) 명시적 검증
        exp = payload.get("exp")
        if not exp:
            raise HTTPException(
                status_code=401,
                detail="Token missing expiration time"
            )

        current_time = datetime.now(timezone.utc).timestamp()
        if current_time >= exp:
            raise HTTPException(
                status_code=401,
                detail="Token has expired"
            )

        # 발행 시간(iat) 명시적 검증 (미래 토큰 방지)
        iat = payload.get("iat")
        if not iat:
            raise HTTPException(
                status_code=401,
                detail="Token missing issued at time"
            )

        if iat > current_time:
            raise HTTPException(
                status_code=401,
                detail="Token issued in the future"
            )

        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=401,
            detail="Could not validate credentials"
        )


def get_current_user_from_token(authorization: str = Header(...)) -> Dict:
    """
    Authorization 헤더에서 JWT 토큰을 추출하고 검증하여 사용자 정보 반환

    Args:
        authorization: Authorization 헤더 (Bearer {token} 형식)

    Returns:
        Dict: 사용자 정보 (user_id, email, group_id, role)

    Raises:
        HTTPException: 토큰이 유효하지 않은 경우
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization header format. Use 'Bearer {token}'"
        )

    token = authorization.replace("Bearer ", "")
    payload = verify_token(token, token_type="access")

    # 필수 필드 확인
    user_id = payload.get("user_id")
    email = payload.get("email")
    group_id = payload.get("group_id")
    role = payload.get("role")

    if not all([user_id, email, group_id, role]):
        raise HTTPException(
            status_code=401,
            detail="Invalid token payload"
        )

    return {
        "user_id": UUID(user_id),
        "email": email,
        "group_id": UUID(group_id),
        "role": role
    }


def get_user_id_from_refresh_token(token: str) -> UUID:
    """
    Refresh Token에서 user_id 추출

    Args:
        token: Refresh Token

    Returns:
        UUID: 사용자 ID

    Raises:
        HTTPException: 토큰이 유효하지 않은 경우
    """
    payload = verify_token(token, token_type="refresh")
    user_id = payload.get("user_id")

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token payload"
        )

    return UUID(user_id)
