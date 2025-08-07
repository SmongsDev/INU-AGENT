from fastapi import APIRouter
from app.schemas.sample import Tier1

router = APIRouter()

@router.post("/sample")
async def process_tier1_data(tier1_data: Tier1) -> str:
    return f"처리된 Data: IP {tier1_data.source_ip}에서 {tier1_data.event_type} 이벤트 발생, 에러 코드: {tier1_data.error_code or '없음'}"