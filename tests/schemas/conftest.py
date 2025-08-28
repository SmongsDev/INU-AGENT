import os
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
from app.db.models import Base

# .env 파일 로드
load_dotenv(os.path.join('.env'))

# 실제 데이터베이스 URL에서 테스트용 데이터베이스 URL 생성
TEST_DATABASE_URL = os.getenv("DATABASE_URL")
if not TEST_DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is not set")

@pytest.fixture(scope="session")
def engine():
    """테스트 데이터베이스 엔진 생성"""
    engine = create_engine(TEST_DATABASE_URL)
    yield engine
    engine.dispose()

@pytest.fixture(scope="session")
def tables(engine):
    """테스트용 테이블 생성 및 삭제"""
    Base.metadata.create_all(engine)
    yield
    #Base.metadata.drop_all(engine)

@pytest.fixture
def db_session(engine, tables):
    """테스트용 데이터베이스 세션"""
    connection = engine.connect()
    transaction = connection.begin()
    Session = sessionmaker(bind=connection)
    session = Session()

    yield session

    session.close()
    transaction.rollback()
    connection.close()