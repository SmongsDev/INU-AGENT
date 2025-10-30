from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import os

# .env 파일 로드
load_dotenv()

# 환경변수에서 DB URL 불러오기
DATABASE_URL = os.getenv("TEST_DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL is not set in the environment variables.")

# SQLAlchemy 엔진 생성 (커넥션 풀 최적화)
engine = create_engine(
    DATABASE_URL,
    pool_size=20,           # 기본 풀 크기 (5 → 20)
    max_overflow=30,        # 초과 허용 연결 (10 → 30)
    pool_recycle=3600,      # 1시간마다 연결 재생성
    pool_pre_ping=True,     # 연결 사용 전 health check
    echo=False
)

# 세션 팩토리
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
