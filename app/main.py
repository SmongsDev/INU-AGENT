import logging
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.services.events_service import EventService
from app.services.ml_analysis_service import MLAnalysisService
from app.api.v1 import router as v1

logger = logging.getLogger(__name__)

async def periodic_fetch(interval_minutes: int = 50):
    group_id = "accbe9c0-7ae8-4aa3-a0c7-9992e009f8cf"
    event_service = EventService(group_id=group_id)
    ml_service = MLAnalysisService(group_id=group_id)

    while True:
        # 새 이벤트 가져오기
        events = await event_service.fetch_new_events()

        if events:
            # ML 분석 수행 및 자동 분기 처리 (비동기)
            stats = await ml_service.analyze_events(events)
            logger.info(f"처리 완료: {stats}")
        else:
            logger.debug("새 이벤트 없음")

        await asyncio.sleep(interval_minutes * 60)  # 5분을 초 단위로 변환

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 주기적 실행 태스크 시작
    monitoring_task = asyncio.create_task(periodic_fetch())
    yield
    # 애플리케이션 종료 시 태스크 취소
    monitoring_task.cancel()
    try:
        await monitoring_task
    except asyncio.CancelledError:
        pass

app = FastAPI(lifespan=lifespan)

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://inu-sdev3.my"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(v1, prefix="/api/v1")

@app.get("/")
async def root():
    return {"message": "INU-AGENT API 서버가 실행 중입니다."}