import asyncio
import subprocess
import sys
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.services.events_service import EventService
from app.api.v1 import router as v1

async def periodic_fetch(interval_minutes: int = 5):
    event_service = EventService(group_id="accbe9c0-7ae8-4aa3-a0c7-9992e009f8cf")
    while True:
        await event_service.fetch_new_events()
        await asyncio.sleep(interval_minutes * 60)  # 5분을 초 단위로 변환

async def periodic_ml_analysis(interval_minutes: int = 30):
    project_root = Path(__file__).parent.parent
    ml_script = project_root / "ml" / "run_analysis.py"
    
    while True:
        try:
            result = await asyncio.create_subprocess_exec(
                sys.executable, str(ml_script), "predict_threats",
                "--batch-size", "5000",
                cwd=str(project_root),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                print("ML 분석 완료")
                if stdout:
                    print(f"출력: {stdout.decode()}")
            else:
                print(f"ML 분석 실패 (코드: {result.returncode})")
                if stderr:
                    print(f"오류: {stderr.decode()}")
                    
        except Exception as e:
            print(f"ML 분석 중 예외 발생: {e}")
            
        await asyncio.sleep(interval_minutes * 60)  # 30분을 초 단위로 변환

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 주기적 실행 태스크 시작
    monitoring_task = asyncio.create_task(periodic_fetch())
    ml_analysis_task = asyncio.create_task(periodic_ml_analysis())
    yield
    # 애플리케이션 종료 시 태스크 취소
    monitoring_task.cancel()
    ml_analysis_task.cancel()
    try:
        await monitoring_task
    except asyncio.CancelledError:
        pass
    try:
        await ml_analysis_task
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