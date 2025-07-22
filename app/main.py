import asyncio
from fastapi import FastAPI
from contextlib import asynccontextmanager

from app.services.data_sync_service import DataSyncService
from app.core.logger import get_logger

logger = get_logger(__name__)

# 데이터 동기화 서비스 인스턴스
data_sync_service = DataSyncService()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 애플리케이션 시작 시 데이터 동기화 서비스 시작
    logger.info("CloudTrail 이벤트 동기화 서비스를 시작합니다...")
    
    # 백그라운드 태스크로 데이터 동기화 시작
    asyncio.create_task(data_sync_service.start_sync("cloudtrail", interval_minutes=1))
    
    yield
    
    # 애플리케이션 종료 시 필요한 정리 작업
    logger.info("애플리케이션을 종료합니다...")

app = FastAPI(lifespan=lifespan)

@app.get("/")
async def root():
    return {"message": "INU-AGENT API 서버가 실행 중입니다."}
