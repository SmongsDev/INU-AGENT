from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from uuid import UUID
from datetime import datetime

from app.db.session import get_db
from app.core.auth import get_group_id_from_token
from app.schemas.chat import ChatSummaryRequest, ChatSummaryResponse
from app.services.chat_service import ChatService
from app.services.openai_service import OpenAIService
from app.core.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()

# OpenAI 서비스 싱글톤 인스턴스
openai_service = None


def get_openai_service() -> OpenAIService:
    """OpenAI 서비스 인스턴스 반환 (싱글톤)"""
    global openai_service
    if openai_service is None:
        openai_service = OpenAIService()
    return openai_service


@router.post("/chat/summary", response_model=ChatSummaryResponse)
def create_chat_summary(
    request: ChatSummaryRequest,
    group_id: UUID = Depends(get_group_id_from_token),
    db: Session = Depends(get_db)
):
    """
    챗봇 위협 요약 API

    특정 기간의 보안 위협 데이터를 조회하고 AI를 활용하여 요약 및 분석 결과를 제공합니다.

    Args:
        request: 요청 데이터 (start_date, end_date, question)
        group_id: 인증된 사용자의 그룹 ID
        db: 데이터베이스 세션

    Returns:
        ChatSummaryResponse: AI 요약 및 통계 데이터

    Raises:
        HTTPException 400: 잘못된 요청 (날짜 형식 오류 등)
        HTTPException 401: 인증 실패
        HTTPException 500: 서버 오류
    """
    try:
        # 1. OpenAI로 질문에서 날짜 범위 추출 (1단계)
        openai = get_openai_service()

        try:
            date_range = openai.extract_date_range(request.question)
            start_dt = datetime.fromisoformat(date_range['start_date']).replace(hour=0, minute=0, second=0, microsecond=0)
            end_dt = datetime.fromisoformat(date_range['end_date']).replace(hour=23, minute=59, second=59, microsecond=999999)
        except Exception as e:
            logger.error(f"Date extraction failed: {str(e)}")
            raise HTTPException(status_code=400, detail=f"날짜 추출 실패: {str(e)}")

        # 2. 위협 데이터 조회
        try:
            threat_data = ChatService.fetch_threat_data(
                db=db,
                group_id=group_id,
                start_date=start_dt,
                end_date=end_dt
            )
        except Exception as e:
            logger.error(f"Failed to fetch threat data: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"위협 데이터 조회 실패: {str(e)}"
            )

        # 3. 통계 집계
        stats = ChatService.aggregate_statistics(threat_data)

        # 4. 조회 기간 정보
        period = {
            'start': start_dt.strftime('%Y-%m-%d'),
            'end': end_dt.strftime('%Y-%m-%d')
        }

        # 5. AI 요약 생성 (OpenAI, 2단계)
        try:
            summary = openai.generate_summary(
                stats=stats,
                user_question=request.question,
                period=period
            )
        except HTTPException:
            # OpenAI에서 발생한 HTTPException은 그대로 전파
            raise
        except Exception as e:
            logger.error(f"Unexpected error in OpenAI service: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"AI 요약 생성 중 예상치 못한 오류 발생: {str(e)}"
            )

        # 6. 응답 구성
        response = ChatSummaryResponse(
            summary=summary,
            stats=stats,
            period=period,
            extracted_from_question=True
        )

        return response

    except HTTPException:
        # 이미 처리된 HTTPException은 그대로 전파
        raise
    except Exception as e:
        # 예상하지 못한 모든 에러
        logger.error(f"Unexpected error in chat summary endpoint: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"서버 오류가 발생했습니다: {str(e)}"
        )
