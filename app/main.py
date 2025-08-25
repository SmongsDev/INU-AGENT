import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.services.cloudtrail_service import CloudTrailService
from app.core.logger import get_logger
from app.api.v1 import router as v1

logger = get_logger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("CloudTrail 이벤트 동기화 서비스를 시작합니다...")
    
    asyncio.create_task(CloudTrailService(group_id="accbe9c0-7ae8-4aa3-a0c7-9992e009f8cf").start_monitoring(interval_minutes=1))
    
    yield
    
    logger.info("애플리케이션을 종료합니다...")

app = FastAPI(lifespan=lifespan)

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(v1, prefix="/api/v1")

@app.get("/")
async def root():
    return {"message": "INU-AGENT API 서버가 실행 중입니다."}